#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

#include <fmt/format.h>
#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <wiifs/fs.h>

#include "common/common_types.h"

static std::unique_ptr<wiifs::FileSystem> s_fs;
static size_t s_number_of_handles = 0;

namespace {
int TranslateErrorCode(wiifs::ResultCode wii_code) {
  fmt::print(stderr, "got result code {}\n", -int(wii_code));
  switch (wii_code) {
  case wiifs::ResultCode::Success:
    return 0;
  case wiifs::ResultCode::Invalid:
    return -EINVAL;
  case wiifs::ResultCode::AccessDenied:
    return -EACCES;
  case wiifs::ResultCode::SuperblockWriteFailed:
  case wiifs::ResultCode::SuperblockInitFailed:
    return -EIO;
  case wiifs::ResultCode::AlreadyExists:
    return -EEXIST;
  case wiifs::ResultCode::NotFound:
    return -ENOENT;
  case wiifs::ResultCode::FstFull:
  case wiifs::ResultCode::NoFreeSpace:
    return -ENOSPC;
  case wiifs::ResultCode::NoFreeHandle:
    return -EMFILE;
  case wiifs::ResultCode::TooManyPathComponents:
    return -ENAMETOOLONG;
  case wiifs::ResultCode::InUse:
    return -EBUSY;
  case wiifs::ResultCode::BadBlock:
  case wiifs::ResultCode::EccError:
  case wiifs::ResultCode::CriticalEccError:
    return -EIO;
  case wiifs::ResultCode::FileNotEmpty:
    return -EPERM;
  case wiifs::ResultCode::CheckFailed:
  case wiifs::ResultCode::UnknownError:
  default:
    return -EIO;
  }
}

std::tuple<wiifs::FileMode, wiifs::FileMode, wiifs::FileMode> ConvertModeToWiiMode(mode_t mode) {
  auto owner_mode = wiifs::FileMode::None;
  auto group_mode = wiifs::FileMode::None;
  auto other_mode = wiifs::FileMode::None;
  if (mode & S_IRUSR)
    owner_mode |= wiifs::FileMode::Read;
  if (mode & S_IWUSR)
    owner_mode |= wiifs::FileMode::Write;
  if (mode & S_IRGRP)
    group_mode |= wiifs::FileMode::Read;
  if (mode & S_IWGRP)
    group_mode |= wiifs::FileMode::Write;
  if (mode & S_IROTH)
    other_mode |= wiifs::FileMode::Read;
  if (mode & S_IWOTH)
    other_mode |= wiifs::FileMode::Write;
  return {owner_mode, group_mode, other_mode};
}

int CheckIsFile(const char* path) {
  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());
  if (!meta->is_file)
    return -EISDIR;
  return 0;
}

int CheckIsDirectory(const char* path) {
  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());
  if (meta->is_file)
    return -ENOTDIR;
  return 0;
}

void wiifs_destroy(void*) {
  fmt::print(stderr, "{}\n", __FUNCTION__);
  s_fs->Close(wiifs::INTERNAL_FD);
}

int wiifs_getattr(const char* path, struct stat* st) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());

  st->st_dev = 0;
  st->st_ino = meta->fst_index;
  st->st_mode = meta->is_file ? S_IFREG : S_IFDIR;
  if ((u8(meta->owner_mode & wiifs::FileMode::Read)) != 0)
    st->st_mode |= S_IRUSR;
  if (u8(meta->owner_mode & wiifs::FileMode::Write) != 0)
    st->st_mode |= S_IWUSR;
  if (u8(meta->group_mode & wiifs::FileMode::Read) != 0)
    st->st_mode |= S_IRGRP;
  if (u8(meta->group_mode & wiifs::FileMode::Write) != 0)
    st->st_mode |= S_IWGRP;
  if (u8(meta->other_mode & wiifs::FileMode::Read) != 0)
    st->st_mode |= S_IROTH;
  if (u8(meta->other_mode & wiifs::FileMode::Write) != 0)
    st->st_mode |= S_IWOTH;
  st->st_nlink = 1;
  st->st_uid = meta->uid;
  st->st_gid = meta->gid;
  st->st_rdev = 0;
  st->st_size = meta->size;
  st->st_blksize = 0x4000;
  st->st_blocks = std::ceil(meta->size / 512);  // st_blocks uses 512-byte blocks
  st->st_atime = st->st_mtime = st->st_ctime = 0;
  return 0;
}

int wiifs_access(const char* path, int mask) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);
  const auto result = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  return result ? 0 : TranslateErrorCode(result.Error());
}

int wiifs_readdir(const char* path, void* buf, fuse_fill_dir_t fill, off_t, fuse_file_info* info) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  if (int ret = CheckIsDirectory(path))
    return ret;

  const auto result = s_fs->ReadDirectory(wiifs::INTERNAL_FD, path);
  if (!result)
    return TranslateErrorCode(result.Error());

  for (const std::string file : *result) {
    if (fill(buf, file.c_str(), nullptr, 0) != 0)
      break;
  }
  return 0;
}

int wiifs_mkdir(const char* path, mode_t mode) {
  fmt::print(stderr, "{}\n", __FUNCTION__);

  const auto modes = ConvertModeToWiiMode(mode);
  const auto result = s_fs->CreateDirectory(wiifs::INTERNAL_FD, path, 0, std::get<0>(modes),
                                            std::get<1>(modes), std::get<2>(modes));
  return TranslateErrorCode(result);
}

int wiifs_open(const char* path, fuse_file_info* info);
int wiifs_create(const char* path, mode_t mode, fuse_file_info* info) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  const auto modes = ConvertModeToWiiMode(mode);
  const auto result = s_fs->CreateFile(wiifs::INTERNAL_FD, path, 0, std::get<0>(modes),
                                       std::get<1>(modes), std::get<2>(modes));
  if (result != wiifs::ResultCode::Success)
    return TranslateErrorCode(result);

  return wiifs_open(path, info);
}

int wiifs_utimens(const char* path, const timespec* ts) {
  fmt::print(stderr, "{}({}): stubbed\n", __FUNCTION__, path);
  return 0;
}

int wiifs_unlink(const char* path) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  if (int ret = CheckIsFile(path))
    return ret;

  const auto result = s_fs->Delete(wiifs::INTERNAL_FD, path);
  return TranslateErrorCode(result);
}

int wiifs_rmdir(const char* path) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  if (int ret = CheckIsDirectory(path))
    return ret;

  const auto stats = s_fs->GetDirectoryStats(wiifs::INTERNAL_FD, path);
  if (!stats)
    return TranslateErrorCode(stats.Error());
  if (stats->used_inodes > 1)
    return -ENOTEMPTY;

  const auto result = s_fs->Delete(wiifs::INTERNAL_FD, path);
  return TranslateErrorCode(result);
}

int wiifs_rename(const char* from, const char* to) {
  fmt::print(stderr, "{}({}, {})\n", __FUNCTION__, from, to);

  if (CheckIsDirectory(from) == 0) {
    const auto stats = s_fs->GetDirectoryStats(wiifs::INTERNAL_FD, to);
    if (!stats && stats.Error() != wiifs::ResultCode::NotFound)
      return TranslateErrorCode(stats.Error());
    if (stats && stats->used_inodes > 1)
      return -ENOTEMPTY;
  }

  const auto result = s_fs->Rename(wiifs::INTERNAL_FD, from, to);
  return TranslateErrorCode(result);
}

int wiifs_chmod(const char* path, mode_t mode) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());

  const auto modes = ConvertModeToWiiMode(mode);
  const auto result =
      s_fs->SetMetadata(wiifs::INTERNAL_FD, path, meta->uid, meta->gid, meta->attribute,
                        std::get<0>(modes), std::get<1>(modes), std::get<2>(modes));
  return TranslateErrorCode(result);
}

int wiifs_chown(const char* path, uid_t uid, gid_t gid) {
  fmt::print(stderr, "{}({}, {:08x}, {:04x})\n", __FUNCTION__, path, uid, gid);

  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());

  const auto result = s_fs->SetMetadata(wiifs::INTERNAL_FD, path, uid, gid, meta->attribute,
                                        meta->owner_mode, meta->group_mode, meta->other_mode);
  return TranslateErrorCode(result);
}

int wiifs_truncate(const char* path, off_t size) {
  fmt::print(stderr, "{}({}, {})\n", __FUNCTION__, path, size);

  if (int ret = CheckIsFile(path))
    return ret;

  const auto meta = s_fs->GetMetadata(wiifs::INTERNAL_FD, path);
  if (!meta)
    return TranslateErrorCode(meta.Error());

  if (meta->size == 0)
    return 0;

  // Recreate the file. (Other sizes are not supported at the moment.)
  // If there is more than one file, we can't do this safely, so return an error.
  if (size != 0 || s_number_of_handles > 1)
    return -ENOSYS;

  const auto close_result = s_fs->Close(1);
  if (close_result != wiifs::ResultCode::Success)
    return TranslateErrorCode(close_result);

  const auto delete_result = s_fs->Delete(wiifs::INTERNAL_FD, path);
  if (delete_result != wiifs::ResultCode::Success)
    return TranslateErrorCode(delete_result);

  const auto create_result = s_fs->CreateFile(wiifs::INTERNAL_FD, path, meta->attribute,
                                              meta->owner_mode, meta->group_mode, meta->other_mode);
  if (create_result != wiifs::ResultCode::Success)
    return TranslateErrorCode(create_result);

  // Reopen the file. The FD we get back should be identical to the previous one.
  const auto fd = s_fs->OpenFile(0, 0, path, wiifs::FileMode::Read | wiifs::FileMode::Write);
  if (!fd)
    return TranslateErrorCode(fd.Error());
  if (*fd != 1)
    fmt::print(stderr, "oh no\n");
  return 0;
}

int wiifs_open(const char* path, fuse_file_info* info) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  if (int ret = CheckIsFile(path))
    return ret;

  const auto fd = s_fs->OpenFile(0, 0, path, wiifs::FileMode::Read | wiifs::FileMode::Write);
  if (!fd)
    return TranslateErrorCode(fd.Error());

  info->fh = *fd;
  ++s_number_of_handles;
  return 0;
}

int wiifs_read(const char* path, char* buf, size_t size, off_t offset, fuse_file_info* info) {
  fmt::print(stderr, "{}({} fd {}, size {}, offset {})\n", __FUNCTION__, path, info->fh, size,
             offset);

  const auto seek_result = s_fs->SeekFile(info->fh, offset, wiifs::SeekMode::Set);
  if (!seek_result)
    return TranslateErrorCode(seek_result.Error());

  const auto read_count = s_fs->ReadFile(info->fh, reinterpret_cast<u8*>(buf), size);
  if (!read_count)
    return TranslateErrorCode(read_count.Error());

  return *read_count;
}

int wiifs_write(const char* path, const char* buf, size_t size, off_t offset,
                fuse_file_info* info) {
  fmt::print(stderr, "{}({} fd {}, size {}, offset {})\n", __FUNCTION__, path, info->fh, size,
             offset);

  const auto seek_result = s_fs->SeekFile(info->fh, offset, wiifs::SeekMode::Set);
  if (!seek_result)
    return TranslateErrorCode(seek_result.Error());

  const auto write_count = s_fs->WriteFile(info->fh, reinterpret_cast<const u8*>(buf), size);
  if (!write_count)
    return TranslateErrorCode(write_count.Error());

  return *write_count;
}

int wiifs_statfs(const char* path, struct statvfs* stbuf) {
  fmt::print(stderr, "{}\n", __FUNCTION__);

  const auto stats = s_fs->GetNandStats(wiifs::INTERNAL_FD);
  if (!stats)
    return -EIO;

  stbuf->f_bsize = stbuf->f_frsize = stats->cluster_size;
  stbuf->f_blocks =
      stats->used_clusters + stats->free_clusters - stats->reserved_clusters - stats->bad_clusters;
  stbuf->f_bfree = stbuf->f_bavail = stats->free_clusters;
  stbuf->f_files = stats->free_inodes + stats->used_inodes;
  stbuf->f_ffree = stbuf->f_favail = stats->free_inodes;
  stbuf->f_fsid = 0;
  stbuf->f_flag = 0;
  stbuf->f_namemax = 12;
  return 0;
}

int wiifs_release(const char* path, fuse_file_info* info) {
  fmt::print(stderr, "{}({})\n", __FUNCTION__, path);

  const auto result = s_fs->Close(info->fh);
  if (result != wiifs::ResultCode::Success)
    return TranslateErrorCode(result);

  --s_number_of_handles;
  return 0;
}

u8* GetNandPointer(const std::string& path) {
  const int fd = open(path.c_str(), O_RDWR);
  if (fd == -1) {
    fmt::print(stderr, "failed to open {}: error {}\n", path, errno);
    return nullptr;
  }

  struct stat file_stat {};
  const int ret = fstat(fd, &file_stat);
  if (ret == -1) {
    fmt::print(stderr, "failed to stat {}: error {}\n", path, errno);
    return nullptr;
  }
  if (static_cast<size_t>(file_stat.st_size) < wiifs::NAND_SIZE) {
    fmt::print(stderr, "file is too small ({} < {})\n", file_stat.st_size, wiifs::NAND_SIZE);
    return nullptr;
  }

  // XXX: require embedded keys for now
  if (file_stat.st_size != wiifs::NAND_SIZE + 0x400) {
    fmt::print(stderr, "keys must be embedded in the image\n");
    return nullptr;
  }

  auto* nand =
      static_cast<u8*>(mmap(nullptr, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (!nand) {
    fmt::print(stderr, "mmap failed: error {}\n", errno);
    return nullptr;
  }
  return nand;
}

wiifs::FileSystemKeys GetNandKeys(std::uint8_t* nand) {
  wiifs::FileSystemKeys keys;
  constexpr size_t NAND_HMAC_KEY_OFFSET = 0x144;
  constexpr size_t NAND_AES_KEY_OFFSET = 0x158;
  std::copy_n(nand + wiifs::NAND_SIZE + NAND_HMAC_KEY_OFFSET, keys.hmac.size(), keys.hmac.begin());
  std::copy_n(nand + wiifs::NAND_SIZE + NAND_AES_KEY_OFFSET, keys.aes.size(), keys.aes.begin());
  return keys;
}
}  // anonymous namespace

constexpr fuse_operations fuse_ops = [] {
  fuse_operations ops{};
  ops.destroy = wiifs_destroy;
  ops.getattr = wiifs_getattr;
  ops.access = wiifs_access;
  ops.readdir = wiifs_readdir;
  ops.mkdir = wiifs_mkdir;
  ops.create = wiifs_create;
  ops.utimens = wiifs_utimens;
  ops.unlink = wiifs_unlink;
  ops.rmdir = wiifs_rmdir;
  ops.rename = wiifs_rename;
  ops.chmod = wiifs_chmod;
  ops.chown = wiifs_chown;
  ops.truncate = wiifs_truncate;
  ops.open = wiifs_open;
  ops.read = wiifs_read;
  ops.write = wiifs_write;
  ops.statfs = wiifs_statfs;
  ops.release = wiifs_release;
  return ops;
}();

int main(int argc, char** argv) {
  if (argc <= 2 || argv[argc - 2][0] == '-' || argv[argc - 1][0] == '-') {
    fmt::print(stderr, "usage: wiifsfuse [options] nand_image mountpoint\n");
    return 1;
  }

  const std::string nand_image = argv[argc - 2];
  const std::string mountpoint = argv[argc - 1];

  argv[argc - 2] = argv[argc - 1];
  argv[argc - 1] = nullptr;
  --argc;

  auto* nand = GetNandPointer(nand_image);
  if (!nand)
    return 1;

  const wiifs::FileSystemKeys keys = GetNandKeys(nand);
  s_fs = wiifs::FileSystem::Create(nand, keys);
  if (!s_fs) {
    fmt::print(stderr, "failed to create filesystem\n");
    return 1;
  }

  fuse_args args = FUSE_ARGS_INIT(argc, argv);
  fuse_opt_parse(&args, nullptr, nullptr, nullptr);
  fuse_opt_add_arg(&args, "-s");
  const int ret = fuse_main(args.argc, args.argv, &fuse_ops, nullptr);
  fuse_opt_free_args(&args);
  return ret;
}
