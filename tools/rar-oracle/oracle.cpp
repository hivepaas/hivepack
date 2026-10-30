// tools/rar-oracle: UnRAR 7.3.2's own reading of RAR archives, for comparing
// hivepack-rar with it. Built by scripts/testdata.py with UnRAR's sources,
// as UnRAR's library is built (-DRARDLL), and linked with them.
//
// It reads requests from standard input, one a line, and answers each on one
// line:
//
//   list <enable_broken> <hex>
//
// opens the archive (its bytes in hex), with QuickOpen off, as IsArchive
// opens it, then reads every header as Archive::ReadHeader reads them,
// printing what UnRAR keeps of each: the header's fields, the archive's
// state, and the exit code at the end. hivepack-rar answers the same requests
// in crates/rar/tests/oracle.rs, and the answers are compared as text.
//
// UnRAR's license, whose source this program is built with:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

#include "rar.hpp"

#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <string>
#ifdef __linux__
#include <sys/mman.h>
#endif
#include <unistd.h>

static std::string out;

static void put(const char *key, unsigned long long value) {
  char buf[64];
  snprintf(buf, sizeof(buf), " %s=%llx", key, value);
  out += buf;
}

static void put_bytes(const char *key, const byte *data, size_t size) {
  out += " ";
  out += key;
  out += "=";
  if (size == 0)
    out += "-";
  for (size_t i = 0; i < size; i++) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", data[i]);
    out += buf;
  }
}

static void put_wide(const char *key, const std::wstring &s) {
  out += " ";
  out += key;
  out += "=";
  if (s.empty())
    out += "-";
  for (size_t i = 0; i < s.size(); i++) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%s%x", i ? "." : "", (unsigned)(uint32_t)s[i]);
    out += buf;
  }
}

static void put_time(const char *key, RarTime &t) {
  put(key, t.GetUnixNS());
}

static void put_base(BaseBlock &b) {
  put("crc", b.HeadCRC);
  put("type", (unsigned)b.HeaderType);
  put("flags", b.Flags);
  put("size", b.HeadSize);
  put("skip", b.SkipIfUnknown);
}

// What UnRAR does not set is left out: FileHeader::Reset clears only some
// fields, and the others keep what an earlier header or the heap left.
static void put_file(FileHeader &h, RARFORMAT format) {
  if (format == RARFMT14) {
    // RAR 1.4 has no header CRC.
    put("type", (unsigned)h.HeaderType);
    put("flags", h.Flags);
    put("size", h.HeadSize);
  } else
    put_base(h);
  if (format != RARFMT50)
    put("ds", h.DataSize);
  put("host", h.HostOS);
  put("unpver", h.UnpVer);
  put("method", h.Method);
  put("attr", h.FileAttr);
  put_wide("name", h.FileName);
  put_bytes("subdata", h.SubData.data(), h.SubData.size());
  put_time("mtime", h.mtime);
  put_time("ctime", h.ctime);
  put_time("atime", h.atime);
  put("packsize", (unsigned long long)h.PackSize);
  put("unpsize", (unsigned long long)h.UnpSize);
  if (format == RARFMT50)
    put("maxsize", (unsigned long long)h.MaxSize);
  // CRC32 and Digest are a union: only what the type says is meaningful.
  put("hashtype", h.FileHash.Type);
  if (h.FileHash.Type == HASH_RAR14 || h.FileHash.Type == HASH_CRC32)
    put("crc32", h.FileHash.CRC32);
  if (h.FileHash.Type == HASH_BLAKE2)
    put_bytes("digest", h.FileHash.Digest, BLAKE2_DIGEST_SIZE);
  if (format == RARFMT50)
    put("fileflags", h.FileFlags);
  put("splitbefore", h.SplitBefore);
  put("splitafter", h.SplitAfter);
  put("unknownsize", h.UnknownUnpSize);
  put("encrypted", h.Encrypted);
  put("cryptmethod", h.CryptMethod);
  put("saltset", h.SaltSet);
  if (h.SaltSet)
    put_bytes("salt", h.Salt, format == RARFMT50 ? SIZE_SALT50 : SIZE_SALT30);
  if (h.CryptMethod == CRYPT_RAR50)
    put_bytes("initv", h.InitV, sizeof(h.InitV));
  put("usepswcheck", h.UsePswCheck);
  if (h.UsePswCheck)
    put_bytes("pswcheck", h.PswCheck, sizeof(h.PswCheck));
  put("usehashkey", h.UseHashKey);
  put("lg2count", h.Lg2Count);
  put("solid", h.Solid);
  put("dir", h.Dir);
  put("commentinheader", h.CommentInHeader);
  put("version", h.Version);
  put("winsize", h.WinSize);
  put("inherited", h.Inherited);
  put("largefile", h.LargeFile);
  put("subblock", h.SubBlock);
  put("hstype", h.HSType);
  put("redirtype", h.RedirType);
  if (h.RedirType != FSREDIR_NONE)
    put_wide("redirname", h.RedirName);
  put("dirtarget", h.DirTarget);
  put("ownerset", h.UnixOwnerSet);
  if (h.UnixOwnerSet) {
    put("ownernumeric", h.UnixOwnerNumeric);
    put("groupnumeric", h.UnixGroupNumeric);
    put_bytes("owner", (const byte *)h.UnixOwnerName, strlen(h.UnixOwnerName));
    put_bytes("group", (const byte *)h.UnixGroupName, strlen(h.UnixGroupName));
    if (h.UnixOwnerNumeric)
      put("ownerid", (unsigned long long)h.UnixOwnerID);
    if (h.UnixGroupNumeric)
      put("groupid", (unsigned long long)h.UnixGroupID);
  }
}

// What the archive says of itself, after IsArchive and after each header.
static void put_state(Archive &a) {
  put("format", a.Format);
  put("solid", a.Solid);
  put("volume", a.Volume);
  put("maincomment", a.MainComment);
  put("locked", a.Locked);
  put("signed", a.Signed);
  put("firstvolume", a.FirstVolume);
  put("newnumbering", a.NewNumbering);
  put("protected", a.Protected);
  put("encrypted", a.Encrypted);
  put("sfx", a.SFXSize);
  put("broken", a.BrokenHeader);
  put("faileddecryption", a.FailedHeaderDecryption);
  put("volnumber", a.VolNumber);
  put("recovery", (unsigned long long)(long long)a.GetRecoveryPercent());
  put("cur", (unsigned long long)a.CurBlockPos);
  put("next", (unsigned long long)a.NextBlockPos);
  put("headertype", (unsigned)a.GetHeaderType());
}

// Each header by its kind, for the kinds the archive's format reads: RAR 5
// reads main, file, service, encryption and end headers, RAR 1.5 to 4.x no
// encryption header but its old comment, recovery and service headers. Any
// other kind is its ShortBlock.
static int kind_read(Archive &a) {
  int type = a.GetHeaderType();
  switch (type) {
    case HEAD_MAIN: case HEAD_FILE: case HEAD_SERVICE: case HEAD_ENDARC:
      return type;
    case HEAD_CRYPT:
      return a.Format == RARFMT50 ? type : -1;
    case HEAD3_CMT: case HEAD3_PROTECT: case HEAD3_OLDSERVICE:
      return a.Format == RARFMT15 ? type : -1;
  }
  return -1;
}

static void put_header(Archive &a) {
  switch (kind_read(a)) {
    case HEAD_MAIN: {
      MainHeader &m = a.MainHead;
      put_base(m);
      put("highposav", m.HighPosAV);
      put("posav", m.PosAV);
      put("commentinheader", m.CommentInHeader);
      put("packcomment", m.PackComment);
      put("locator", m.Locator);
      put("qopen", m.QOpenOffset);
      put("rr", m.RROffset);
      put_wide("origname", m.OrigName);
      put_time("origtime", m.OrigTime);
      break;
    }
    case HEAD_FILE:
      put_file(a.FileHead, a.Format);
      break;
    case HEAD_SERVICE:
      put_file(a.SubHead, a.Format);
      break;
    case HEAD_CRYPT:
      put_base(a.CryptHead);
      put("usepswcheck", a.CryptHead.UsePswCheck);
      put("lg2count", a.CryptHead.Lg2Count);
      put_bytes("salt", a.CryptHead.Salt, sizeof(a.CryptHead.Salt));
      if (a.CryptHead.UsePswCheck)
        put_bytes("pswcheck", a.CryptHead.PswCheck, sizeof(a.CryptHead.PswCheck));
      break;
    case HEAD_ENDARC:
      put_base(a.EndArcHead);
      put("nextvolume", a.EndArcHead.NextVolume);
      put("datacrc", a.EndArcHead.DataCRC);
      put("revspace", a.EndArcHead.RevSpace);
      put("storevolnumber", a.EndArcHead.StoreVolNumber);
      if (a.EndArcHead.DataCRC)
        put("arcdatacrc", a.EndArcHead.ArcDataCRC);
      if (a.EndArcHead.StoreVolNumber)
        put("endvolnumber", a.EndArcHead.VolNumber);
      break;
    case HEAD3_CMT:
      put_base(a.CommHead);
      put("unpsize", a.CommHead.UnpSize);
      put("unpver", a.CommHead.UnpVer);
      put("method", a.CommHead.Method);
      put("commcrc", a.CommHead.CommCRC);
      break;
    case HEAD3_PROTECT:
      put_base(a.ProtectHead);
      put("ds", a.ProtectHead.DataSize);
      put("version", a.ProtectHead.Version);
      put("recsectors", a.ProtectHead.RecSectors);
      put("totalblocks", a.ProtectHead.TotalBlocks);
      put_bytes("mark", a.ProtectHead.Mark, sizeof(a.ProtectHead.Mark));
      break;
    case HEAD3_OLDSERVICE:
      put_base(a.SubBlockHead);
      put("ds", a.SubBlockHead.DataSize);
      put("subtype", a.SubBlockHead.SubType);
      put("level", a.SubBlockHead.Level);
      if (a.SubBlockHead.SubType == NTACL_HEAD) {
        put("unpsize", a.EAHead.UnpSize);
        put("unpver", a.EAHead.UnpVer);
        put("method", a.EAHead.Method);
        put("subcrc", a.EAHead.EACRC);
      }
      if (a.SubBlockHead.SubType == STREAM_HEAD) {
        put("unpsize", a.StreamHead.UnpSize);
        put("unpver", a.StreamHead.UnpVer);
        put("method", a.StreamHead.Method);
        put("subcrc", a.StreamHead.StreamCRC);
        put_bytes("streamname", (const byte *)a.StreamHead.StreamName.data(),
                  a.StreamHead.StreamName.size());
      }
      break;
    default:
      put_base(a.ShortBlock);
      break;
  }
}

static std::vector<byte> unhex(const char *hex) {
  std::vector<byte> data;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    char pair[3] = {hex[i], hex[i + 1], 0};
    data.push_back((byte)strtoul(pair, NULL, 16));
  }
  return data;
}

static void do_list(int enable_broken, const char *hex) {
  std::vector<byte> data = unhex(hex);
  // In memory, not in /tmp: how far a damaged header can seek depends on the
  // file system. ext4 refuses to seek past 16 TiB, which UnRAR takes for a
  // fatal error, and tmpfs and this file do not. Only Linux's answers are
  // compared, so elsewhere a file will do.
  char path[64];
#ifdef __linux__
  int fd = memfd_create("rar-oracle", 0);
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
#else
  snprintf(path, sizeof(path), "/tmp/rar-oracle-XXXXXX");
  int fd = mkstemp(path);
#endif
  if (fd < 0 || (data.size() && write(fd, data.data(), data.size()) != (ssize_t)data.size())) {
    printf("error writing\n");
    return;
  }

  out = "list";
  ErrHandler.Clean();
  CommandData Cmd;
  Cmd.QOpenMode = QOPEN_NONE;
  try {
    Archive Arc(&Cmd);
    std::string narrow(path);
    std::wstring wide(narrow.begin(), narrow.end());
    if (!Arc.Open(wide)) {
      out += " notopened";
    } else {
      bool ok = Arc.IsArchive(enable_broken != 0);
      out += ok ? " archive" : " notarchive";
      put_state(Arc);
      put_bytes("mark", Arc.MarkHead.Mark, Arc.MarkHead.HeadSize);
      if (ok) {
        size_t size;
        while ((size = Arc.ReadHeader()) != 0) {
          out += " |";
          put("read", size);
          put_state(Arc);
          put_header(Arc);
          Arc.SeekToNext();
        }
        out += " | end";
        put_state(Arc);
      }
    }
  } catch (RAR_EXIT code) {
    put("thrown", code);
  } catch (std::bad_alloc &) {
    out += " badalloc";
  }
  put("exit", ErrHandler.GetErrorCode());
  close(fd);
#ifndef __linux__
  unlink(path);
#endif
  printf("%s\n", out.c_str());
}

int main() {
  setenv("TZ", "UTC", 1);
  tzset();
  setlocale(LC_ALL, "C.UTF-8");

  std::string line;
  int c;
  while (true) {
    line.clear();
    while ((c = getchar()) != EOF && c != '\n')
      line += (char)c;
    if (c == EOF && line.empty())
      break;
    char *words[4];
    int count = 0;
    for (char *w = strtok(&line[0], " "); w && count < 4; w = strtok(NULL, " "))
      words[count++] = w;
    if (count == 3 && strcmp(words[0], "list") == 0)
      do_list(atoi(words[1]), words[2]);
    else if (count == 2 && strcmp(words[0], "list") == 0)
      do_list(atoi(words[1]), "");
    else
      printf("unknown request\n");
    fflush(stdout);
  }
  return 0;
}
