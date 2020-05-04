/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64


#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>
/* add by yangke start */
//#include <igraph.h>
#include "map.h"
#include "hashset.h"
#include "hashset_itr.h"
/* add by yangke end */

#include <math.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#  define HAVE_AFFINITY 1
#endif /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */


EXP_ST u8 *in_dir,                    /* Input directory with test cases  */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *sync_dir,                  /* Synchronization directory        */
          *sync_id,                   /* Fuzzer ID                        */
          *use_banner,                /* Display banner                   */
          *in_bitmap,                 /* Input bitmap                     */
          *doc_path,                  /* Path to documentation dir        */
          *target_path,               /* Path to target binary            */
          *orig_cmdline,              /* Original command line            */
          *temp_dir;                  /* Temp dir that contains CFG info */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit  = MEM_LIMIT;    /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

static u8 cooling_schedule = 0;      /* Cooling schedule for directed fuzzing */
enum {
  /* 00 */ SAN_EXP,                   /* Exponential schedule             */
  /* 01 */ SAN_LOG,                   /* Logarithmical schedule           */
  /* 02 */ SAN_LIN,                   /* Linear schedule                  */
  /* 03 */ SAN_QUAD                   /* Quadratic schedule               */
};

EXP_ST u8  skip_deterministic,        /* Skip deterministic stages?       */
           force_deterministic,       /* Force deterministic stages?      */
           use_splicing,              /* Recombine input files?           */
           dumb_mode,                 /* Run in non-instrumented mode?    */
           score_changed,             /* Scoring for favorites changed?   */
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming an older fuzzing job?   */
           timeout_given,             /* Specific timeout given?          */
           not_on_tty,                /* stdout is not a tty              */
           term_too_small,            /* terminal dimensions too small    */
           uses_asan,                 /* Target uses ASAN?                */
           no_forkserver,             /* Disable forkserver?              */
           crash_mode,                /* Crash mode! Yeah!                */
           in_place_resume,           /* Attempt in-place resume?         */
           auto_changed,              /* Auto-generated tokens changed?   */
           no_cpu_meter_red,          /* Feng shui on the status screen   */
           no_arith,                  /* Skip most arithmetic ops         */
           shuffle_queue,             /* Shuffle input queue?             */
           bitmap_changed = 1,        /* Time to update bitmap?           */
           qemu_mode,                 /* Running in QEMU mode?            */
           skip_requested,            /* Skip request, via SIGUSR1        */
           run_over10m,               /* Run time over 10 minutes?        */
           persistent_mode;           /* Running in persistent mode?      */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1,            /* PID of the fuzzed program        */
           out_dir_fd = -1;           /* FD of the lock file              */

EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  */



EXP_ST u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
           virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

#ifdef __x86_64__
EXP_ST u64 virgin_var_bits[MAP_SIZE]; /* Regions yet untouched by fuzzing,
                                       specially for key branch variable map
                                       # add by yangke #                  */
#else
EXP_ST u32 virgin_var_bits[MAP_SIZE]; /* Regions yet untouched by fuzzing,
                                       specially for key branch variable map
                                       # add by yangke #                  */
#endif


static u8  var_bytes[MAP_SIZE];       /* Bytes that appear to be variable */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen = 1,  /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

EXP_ST u32 queued_paths,              /* Total number of queued testcases */
           queued_variable,           /* Testcases with variable behavior */
           queued_at_start,           /* Total number of initial inputs   */
           queued_discovered,         /* Items discovered during this run */
           queued_imported,           /* Items imported via -S            */
           queued_favored,            /* Paths deemed favorable           */
           queued_with_cov,           /* Paths with new coverage bytes    */
           pending_not_fuzzed,        /* Queued but not done yet          */
           pending_favored,           /* Pending favored paths            */
           cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */
           useless_at_start,          /* Number of useless starting paths */
           var_byte_count,            /* Bitmap bytes with var behavior   */
           current_entry,             /* Current queue entry ID           */
           havoc_div = 1;             /* Cycle count divisor for havoc    */

EXP_ST u64 total_crashes,             /* Total number of crashes          */
           unique_crashes,            /* Crashes with unique signatures   */
           total_tmouts,              /* Total number of timeouts         */
           unique_tmouts,             /* Timeouts with unique signatures  */
           unique_hangs,              /* Hangs with unique signatures     */
           total_execs,               /* Total execve() calls             */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms)  */
           last_hang_time,            /* Time for most recent hang (ms)   */
           last_crash_execs,          /* Exec counter at last crash       */
           queue_cycle,               /* Queue round counter              */
           cycles_wo_finds,           /* Cycles without any new paths     */
           trim_execs,                /* Execs done to trim input files   */
           bytes_trim_in,             /* Bytes coming into the trimmer    */
           bytes_trim_out,            /* Bytes coming outa the trimmer    */
           blocks_eff_total,          /* Blocks subject to effector maps  */
           blocks_eff_select;         /* Blocks selected as fuzzable      */

static u32 subseq_tmouts;             /* Number of timeouts in a row      */

static u8 *stage_name = "init",       /* Name of the current fuzz stage   */
          *stage_short,               /* Short stage name                 */
          *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 master_id, master_max;     /* Master instance job splitting    */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
           stage_cur_val;             /* Value used for stage op          */

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32],           /* Patterns found per fuzz stage    */
           stage_cycles[32];          /* Execs per fuzz stage             */

static u32 rand_cnt;                  /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
           total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
           total_bitmap_entries;      /* Number of bitmaps counted        */

static s32 cpu_core_count;            /* CPU core count                   */

#ifdef HAVE_AFFINITY

static s32 cpu_aff = -1;       	      /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

static FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  double distance;                    /* Distance to targets              */
  u32 exec_path_len;                  /* Exec trace length from bitmap    */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top, /* Top of the list                  */
                          *q_prev100; /* Previous 100 marker              */

static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

static struct extra_data* extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data* a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */

static double cur_distance = -1.0;     /* Distance of executed input       */
static double max_distance = -1.0;     /* Maximal distance for any input   */
static double min_distance = -1.0;     /* Minimal distance for any input   */
static u32 t_x = 10;                  /* Time to exploitation (Default: 10 min) */

static u8* (*post_handler)(u8* buf, u32* len);

/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
/* add by yangke start */

/* remember interesting mutaion operation and the operateed positions */

#define MAX_MUT_POS (1024) //4KB
#define MUT_NUM 17
static int mut_cnt[MUT_NUM];//mutation times of a each kind of mution (for value effective filtration).
static map_int_t tmp_pos_map[MUT_NUM];
static u8 tmp_pos_map_initialized=0;
static int tmp_mut_cnt[MUT_NUM];
static int one_fuzz_mut_cnt[MUT_NUM];//mutation times of a each kind of mution(for cov effective statistics)
static int mut_score[MUT_NUM];//based on cov effective statistics
static int mutation_score_initialized;//0 for not, 1 for yes
static int value_changing_mutation_record_initialized;//0 for not, 1 for yes

static unsigned random_mut=0;
static unsigned monitor_mut=0;
static unsigned random_win=0;
static unsigned monitor_win=0;

static unsigned total_mut_cnt=0;//total mutation opteration times
static unsigned total_monitored_mut_cnt=0;//we only monitored some of the mutaions
//so this means times that we current used for mutation proiritization
#define  INIT_THRESHOLD_CYCLES_WO_FINDS 0//threshold for opening mutation prior mode when startup.
#define INIT_MUT_LOOP_BOUND 2 //inital mutation loop bound when searching for good mutation.
#define MAX_MUT_LOOP_BOUND 4 //max mutation loop bound when searching for good mutation.

static unsigned threshold_cycles_wo_finds=INIT_THRESHOLD_CYCLES_WO_FINDS;
//static unsigned t1=0;//cycles_wo_finds:first time >threshold_cycles_wo_finds
//static unsigned t2=0;//cycles_wo_finds:switch to mut_prior_mode
//static unsigned t3=0;//cycles_wo_finds:trigger the change of max_mut_loop_bound
static unsigned max_mut_loop_bound=INIT_MUT_LOOP_BOUND;
static int mut_prior_mode=0;//flags that indicate we are in mutation prior mode
//TODO: add more mutator argument info other than position ...
static u32 max_trace_len=0;
static u32 cur_trace_len=0;
static double avg_hit_cnt=0.0;
static u32 trace_classes=0;

enum {
  /* 00 */ FIELD_BASED,                   /* Field-based condition           */
  /* 01 */ STATE_BASED,                   /* State-based condition           */
  /* 02 */ UNKNOWN                        /* Currently unknown               */
};
/* SCAN,JUDGE,ANSWER is three stage designed for solving obvious field comparision condition
 * In these stage, it disable slicing, (havoc)mutate one byte a time*/
enum {
  /* 00 */ SCAN,                       /* Scanning for affective bytes               */
  /* 01 */ JUDGE,                      /* Judging whether it is field based          */
  /* 02 */ ANSWER,                     /* Solve this branch with aquired answers     */
  /* 03 */ RANDOM                     /* Freedom fuzzing as AFLGO if we cannot
	   										 solve it  during solving stage.         */
};

typedef struct BasicBlock{
	int rid;
	char bbname[256];
	double distance;//distance
	u8 cov;//cov:1,uncov:0
	u8 out_degree;
	u8 is_margin;//yes:1,no:0
	u8 is_margin_last_check;
	u16 margin_history;
	u8 branch_type;
	char * answer_str;
	map_int_t * successors;
	map_int_t * invalid_positions;
	//char nid[32];
	//char key_str[1024];
} Node;

typedef struct record{
	hashset_t B;//margin branches that is affected
	int  M[17];//effective mutation list
	map_int_t P;//effective fuzzing position
	double distance;
	struct record * next;
} Record;

typedef struct strategy{
	Record * record_list;
	map_void_t record_map;
	u32 trace_len;
	u32 hit_cnt;
} Strategy;

typedef struct {
	int cur_size;
	int max_size;
	void ** elements;
} Container;

typedef struct {
   char * fname;
   map_void_t * rid2node;
   Container * margin_bbs;
   Container * pmbbs;//possible margin bbs
} CFG;

Container * CFGs=NULL;

static int margin_bb_count=0;
static double min_d=1.7E+308;//min distance of margin basic block, initialize in loadCFG().
static double min_gd=1.7E+308;//min distance of strong connected margin basic block group, initialize in record_value_changing_mutation().
static double max_gd=0.0;//max distance of strong connected margin basic block group, initialize in record_value_changing_mutation().

static map_void_t trace2strategy;
static int cfg_loaded=0;
static int vertex_num=0;
static int edge_num=0;

typedef struct LinkedInteger{
	u64 v;
	struct LinkedInteger * next
} LinkedInteger;
typedef struct LinkListInteger{
	int len;
	struct LinkedInteger * head;
} LinkListInteger;
#define FMAP_LEN 3 //make sure 1<FMAP_LEN<9
typedef struct FMap{
	u8  input;
	u64 output;
	u8  valid;
} FMap;
typedef struct LinkedPosition{
	int pos;
	u8 *answer;
	u8 is_field;
	int fuzz_cnt;
	FMap fmap[FMAP_LEN];
	//LinkListInteger value_list;
	struct LinkedPosition * next;
} LinkedPosition;
typedef struct LinkListPosition{
	int len;
	struct LinkedPosition * head;
}LinkListPosition;
typedef struct Candidate{
	int fuzz_pos;
	u64 base_value;
	LinkedPosition * pos_focus;
	LinkListPosition eff_pos_list;
	struct queue_entry * entry;
	struct Candidate *next;
} Candidate;
typedef struct Target{
	Node* node;
	char function[64];
	u8 solving_stage;
	int scanning_tasks;
	int born_cycle;
	int max_len;
	LinkListInteger answer_list;
	LinkedInteger* answer_focus;
	LinkListInteger value_list;
	int c_list_len;
	Candidate * c_list;
	Candidate * c_focus;
} Target;
Target * target_bb=NULL;
u8 linear_search=0;

static u32 trace_len(u8* mem);
static inline void record_value_changing_mutation(Node * node_list[],int size,Strategy * s);

static inline void cleanup_value_changing_mutation_record();

/* add by yangke end */

/* Fuzzing stages */

enum {
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum {
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void** ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; i++) {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}


#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  d = opendir("/proc");

  if (!d) {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    ck_free(fn);
    fclose(f);

  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;

  if (i == cpu_core_count) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");

  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");

}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; pos++) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */


/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single 
   static buffer. */

static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.995) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


/* Describe integer as memory size. */

static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}


/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}


/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry* q) {

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}


/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  q->distance = cur_distance;
  /* add by yangke start */
  q->exec_path_len = cur_trace_len;
  if(cur_trace_len>max_trace_len) {
	  max_trace_len= cur_trace_len;
  }
  /* add by yangke end */
  if (cur_distance > 0) {

    if (max_distance <= 0) {
      max_distance = cur_distance;
      min_distance = cur_distance;
    }
    if (cur_distance > max_distance) max_distance = cur_distance;
    if (cur_distance < min_distance) min_distance = cur_distance;

  }

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100)) {

    q_prev100->next_100 = q;
    q_prev100 = q;

  }

  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

EXP_ST void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

EXP_ST void write_bitmap(void) {

  u8* fname;
  s32 fd;

  if (!bitmap_changed) return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */

EXP_ST void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8* virgin_map) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

  /* Calculate distance of current input to targets */
  u64* total_distance = (u64*) (trace_bits + MAP_SIZE);
  u64* total_count = (u64*) (trace_bits + MAP_SIZE + 8);

  if (*total_count > 0)
    cur_distance = (double) (*total_distance) / (double) (*total_count);
  else
    cur_distance = -1.0;
  cur_trace_len=trace_len(trace_bits);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

  /* Calculate distance of current input to targets */
  u32* total_distance = (u32*)(trace_bits + MAP_SIZE);
  u32* total_count = (u32*)(trace_bits + MAP_SIZE + 4);

  if (*total_count > 0) {
    cur_distance = (double) (*total_distance) / (double) (*total_count);
  else
    cur_distance = -1.0;

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;
        /* add by yangke start */
        //if (ret==2){
        //	OKF("interesting!!!! ret=%d\n",ret);
		//	OKF("vir:%x %x %x %x %x %x %x %x\n",vir[0],vir[1],vir[2],vir[3],vir[4],vir[5],vir[6],vir[7]);
		//	OKF("cur:%x %x %x %x %x %x %x %x\n",cur[0],cur[1],cur[2],cur[3],cur[4],cur[5],cur[6],cur[7]);
        //}
        /* add by yangke end */

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}
/* add by yangke start */

/* log to out_dir */
static inline void log2file_and_free(char * fn,char *info)
{
	int debug_fd = open(fn, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (debug_fd < 0) PFATAL("Unable to create '%s'", fn);
	ck_write(debug_fd, info, strlen(info), fn);
	close(debug_fd);
	ck_free(info);
	ck_free(fn);
}

/* Check if the current execution path brings any change for the map of margin key
 * branch variable values in every execution point.
 * Update virgin_var_bits to reflect the finds. Returns 1 for finding the change, and 0 otherwise.
 * This information is for prioritizing mutation positions and operations
 */
static u32 remember[256];
static int cur_pos=-1;
static inline int seen(u32 value)
{
	if(cur_pos==-1){
		for(int i=0;i<121;i++){
			remember[i]=0xffffffff;
		}
		remember[0]=value;
		cur_pos=1;
		return 0;
	}else{
		int i=0;
		for(i=0;i<cur_pos;i++){
			if(remember[i]==value){
				return 1;
			}
		}
		remember[i]=value;
		cur_pos++;
		return 0;
	}

}
static  inline int has_new_var_bits2()
{
	int ret=0;
	//u64* cur = (u64*)(trace_bits+MAP_SIZE+16);
	u32 cksum = hash32(trace_bits+MAP_SIZE+16, (MAP_SIZE-2)<<3, HASH_CONST);
	if(!seen(cksum)){
		//OKF("cksum=%lx",cksum);
		ret=-1;
	}

	return ret;
}

#ifdef __x86_64__
  static  inline int has_new_var_bits(u64* virgin_var_map, Node * node_list[]) {
	int ret = 0;//invalid distance value
	u64* vir = (u64*) virgin_var_map;
	u64* cur = (u64*)(trace_bits+MAP_SIZE+16);
	//OKF("margin_bb_count=%d",margin_bb_count);
	for (int i=0;i<CFGs->cur_size;i++) {
		CFG * cfg=(CFG *)CFGs->elements[i];
		if(!cfg->rid2node) FATAL("CFG of %s() is empty! rid2node=(nil)",cfg->fname);
		if(!cfg->margin_bbs) FATAL("Margin BB of %s() not initialized! cfg->margin_bbs=(nil)",cfg->fname);
		Container * margin_bbs = cfg->margin_bbs;
		for(int j=0;j<margin_bbs->cur_size;j++){
			Node * node = (Node*)margin_bbs->elements[j];
			int rid=node->rid;
			if(unlikely(vir[rid] & (~cur[rid]))){
				vir[rid]&=cur[rid];
				node_list[ret++]=node;
			}
		}
	}
	return ret;
  }
#else
  static inline int has_new_var_bits(u32* virgin_var_map, Node * node_list[]) {
	    int ret = 0;//invalid distance value
	    u32* vir = (u32*) virgin_var_map;
	    u32* cur = (u32*)(trace_bits+MAP_SIZE+8);

	    for (int i=0;i<CFGs->cur_size;i++) {
			CFG * cfg=(CFG *)CFGs->elements[i];
			if(!cfg->rid2node) FATAL("CFG of %s() is empty! rid2node=(nil)",cfg->fname);
			Container * margin_bbs = cfg->margin_bbs;
			for(int j=0;j<margin_bbs->cur_size;j++){
				Node * node = (Node*)margin_bbs->elements[j];
				int rid=node->rid;
				if(unlikely(vir[rid] & (~cur[rid]))){
					vir[rid]&=cur[rid];
					node_list[ret++]=node;
				}
			}
		}
	    return ret;
  }
#endif /* ^__x86_64__ */
/* add by yangke end */


/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


#define FF(_b)  (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}

/* add by yangke start */
static u32 trace_len(u8* mem) {

	u8* ptr = mem;
	u32  ret = 0;
	for(u32 i=0;i<MAP_SIZE;i++,ptr++){
		if (((*ptr)&0xff)&&(*ptr)!=0xff){
			ret+=*ptr;//TODO: fix integer overflow
		}
	}
	return ret;

}
/* add by yangke end */

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = { 

  [0]         = 1,
  [1 ... 255] = 128

};

#ifdef __x86_64__

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;

    mem++;
  }

}

#endif /* ^__x86_64__ */


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];


EXP_ST void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}


#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}


/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }

       score_changed = 1;

     }

}


/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}


/* Configure shared memory and virgin_bits. This is called at startup. */

EXP_ST void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);
#ifdef __x86_64__
  memset(virgin_var_bits, 255, MAP_SIZE<<3);
  shm_id = shmget(IPC_PRIVATE, MAP_SIZE + 16 + (MAP_SIZE<<3), IPC_CREAT | IPC_EXCL | 0600);
#else
  memset(virgin_var_bits, 255, MAP_SIZE<<2);
  shm_id = shmget(IPC_PRIVATE, MAP_SIZE + 16 + (MAP_SIZE<<2), IPC_CREAT | IPC_EXCL | 0600);
#endif
  /* Allocate 24 byte more for distance info */
  /* add by yangke:
   * (1) It seems only allocate 16 byte for distance info
   * (2) allocate 64KB to record triggerd BB RandomId
   * (3) allocate 64KB to map branch variables' values for each BB */
  /* : why not 16 */



  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");
#ifdef __x86_64__
  memset(trace_bits, 255, MAP_SIZE + 16 + (MAP_SIZE<<3));
#else
  memset(trace_bits, 255, MAP_SIZE + 8 + (MAP_SIZE<<2));
#endif
}


/* Load postprocessor, if available. */

static void setup_post(void) {

  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");

}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK)) in_dir = fn; else ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);

  }

  if (shuffle_queue && nl_cnt > 1) {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);

  }

  free(nl); /* not tracked */

  if (!queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);

  }

  last_path_time = 0;
  queued_at_start = queued_paths;

}


/* Helper function for load_extras. */

static int compare_extras_len(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e1->len - e2->len;
}

static int compare_extras_use_d(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e2->hit_cnt - e1->hit_cnt;
}


/* Read extras from a file, sort by size. */

static void load_extras_file(u8* fname, u32* min_len, u32* max_len,
                             u32 dict_level) {

  FILE* f;
  u8  buf[MAX_LINE];
  u8  *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");

  if (!f) PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr)) lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr)) rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_') lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      lptr++;
      if (atoi(lptr) > dict_level) continue;
      while (isdigit(*lptr)) lptr++;

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=') lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr) {

      char* hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);

        case '\\':

          lptr++;

          if (*lptr == '\\' || *lptr == '"') {
            *(wptr++) = *(lptr++);
            klen++;
            break;
          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          klen++;

          break;

        default:

          *(wptr++) = *(lptr++);
          klen++;

      }

    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;
    if (*max_len < klen) *max_len = klen;

    extras_cnt++;

  }

  fclose(f);

}


/* Read extras from the extras directory and sort them by size. */

static void load_extras(u8* dir) {

  DIR* d;
  struct dirent* de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8* x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d) {

    if (errno == ENOTDIR) {
      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size) min_len = st.st_size;
    if (max_len < st.st_size) max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *
               sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len  = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    extras_cnt++;

  }

  closedir(d);

check_and_sort:

  if (!extras_cnt) FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);

}




/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}


/* Maybe add automatic extra. */

static void maybe_add_auto(u8* mem, u32 len) {

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS) return;

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; i++)
    if (mem[0] ^ mem[i]) break;

  if (i == len) return;

  /* Reject builtin interesting values. */

  if (len == 2) {

    i = sizeof(interesting_16) >> 1;

    while (i--) 
      if (*((u16*)mem) == interesting_16[i] ||
          *((u16*)mem) == SWAP16(interesting_16[i])) return;

  }

  if (len == 4) {

    i = sizeof(interesting_32) >> 2;

    while (i--) 
      if (*((u32*)mem) == interesting_32[i] ||
          *((u32*)mem) == SWAP32(interesting_32[i])) return;

  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len) break;

  for (; i < extras_cnt && extras[i].len == len; i++)
    if (!memcmp_nocase(extras[i].data, mem, len)) return;

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; i++) {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len)) {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;

    }

  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (a_extras_cnt < MAX_AUTO_EXTRAS) {

    a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                sizeof(struct extra_data));

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);
    a_extras[a_extras_cnt].len  = len;
    a_extras_cnt++;

  } else {

    i = MAX_AUTO_EXTRAS / 2 +
        UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);

    a_extras[i].data    = ck_memdup(mem, len);
    a_extras[i].len     = len;
    a_extras[i].hit_cnt = 0;

  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),
        sizeof(struct extra_data), compare_extras_len);

}


/* Save automatically generated extras. */

static void save_auto(void) {

  u32 i;

  if (!auto_changed) return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++) {

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}


/* Load automatically generated extras. */

static void load_auto(void) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++) {

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8* fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);

    if (fd < 0) {

      if (errno != ENOENT) PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0) PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);

    close(fd);
    ck_free(fn);

  }

  if (i) OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else OKF("No auto-generated dictionary tokens to reuse.");

}


/* Destroy extras. */

static void destroy_extras(void) {

  u32 i;

  for (i = 0; i < extras_cnt; i++) 
    ck_free(extras[i].data);

  ck_free(extras);

  for (i = 0; i < a_extras_cnt; i++) 
    ck_free(a_extras[i].data);

  ck_free(a_extras);

}


/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

EXP_ST void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else if (!mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ?
         "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
         "      reached before the program terminates.\n\n" : "",
         DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv, u32 timeout) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE + 16);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

    }

  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_TMOUT;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (skip_at) ck_write(fd, mem, skip_at, out_file);

  if (tail_len) ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* This is relevant when test cases are added w/out save_if_interesting */

    if (q->distance <= 0) {

      /* This calculates cur_distance */
      has_new_bits(virgin_bits);

      q->distance = cur_distance;
      if (cur_distance > 0) {

        if (max_distance <= 0) {
          max_distance = cur_distance;
          min_distance = cur_distance;
        }
        if (cur_distance > max_distance) max_distance = cur_distance;
        if (cur_distance < min_distance) min_distance = cur_distance;

      }

    }

    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;

          }

        }

        var_detected = 1;

      } else {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);

      }

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected) {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }

  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();

  return fault;

}


/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void) {

  u32 i;

  if (count_bytes(trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {

      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_TMOUT:

        if (timeout_given) {

          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        }

      case FAULT_CRASH:  

        if (crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (mem_limit) {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        useless_at_start++;

        if (!in_bitmap && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;

  }

  if (cal_failures) {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}


/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) 
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);

}


static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {

      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (max_depth < q->depth) max_depth = q->depth;

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8* use_name = strstr(rsl, ",orig:");

      if (use_name) use_name += 6; else use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);

    q = q->next;
    id++;

  }

  if (in_place_resume) nuke_resume_dir();

}


#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);

  } else {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);

}
void destroy_template_strategy(Strategy *s)
{
	map_deinit(&s->record_map);
	Record *r;
	while(s->record_list!=NULL){
		r=s->record_list;
		s->record_list=r->next;
		hashset_destroy(r->B);
		map_deinit(&r->P);
		free(r);
	}
	free(s);
}
void destroy_records()
{
	const char *key;
	map_iter_t iter = map_iter(&trace2strategy);
	while ((key = map_next(&trace2strategy, &iter))) {
	  Strategy * s=(Strategy *) *map_get(&trace2strategy, key);
	  destroy_template_strategy(s);
	}
	for(int i=0;i<MUT_NUM;i++){
		map_deinit(&tmp_pos_map[i]);
	}
	map_deinit(&trace2strategy);
	value_changing_mutation_record_initialized=0;
	tmp_pos_map_initialized=0;
}
static inline void init_container(Container * c){
	c->cur_size=0;
	c->max_size=256;
	c->elements=malloc(256*sizeof(Node*));
}
static inline void add_element(Container * c, void * element){
	if(c->cur_size>=c->max_size){
		c->max_size<<=1;
		c->elements=(void**)realloc(c->elements,c->max_size);
	}
	c->elements[c->cur_size++]=element;
}
static inline void destroy_container(Container * c){
	free(c->elements);
	c->cur_size=0;
	c->max_size=0;
}
static inline void remove_candidates();
static inline void remove_values();
static inline void destroy_target(){
	remove_candidates();
	remove_values(&target_bb->value_list);
	remove_values(&target_bb->answer_list);
	free(target_bb);
}

void destroy_all_cfg()
{
	for (int i=0;i<CFGs->cur_size;i++) {
	    CFG * cfg=(CFG *)CFGs->elements[i];
	    if(!cfg->rid2node) FATAL("CFG of %s() is empty! rid2node=(nil)",cfg->fname);
	    map_void_t * rid2node = cfg->rid2node;
	    const char *rid_str;
	    map_iter_t node_iter = map_iter(rid2node);
	    while ((rid_str = map_next(rid2node, &node_iter))) {
	    	void **q=map_get(rid2node, rid_str);
	    	if(!q) FATAL("rid2node is broken, rid=%p,node=(nil)",rid_str);
	    	Node * node = (Node *)*q;
	    	if(node->successors){
	    		map_deinit(node->successors);
	    		free(node->successors);
	    		node->successors=NULL;
	    	}
	    	if(node->invalid_positions){
				map_deinit(node->invalid_positions);
				free(node->invalid_positions);
				node->invalid_positions=NULL;
	    	}
	    	if(node->answer_str)free(node->answer_str);
	    	free(node);
	    	node=NULL;
	    }
	    map_deinit(rid2node);
	    free(rid2node);
	    cfg->rid2node=NULL;
	    ck_free(cfg->fname);
	    destroy_container(cfg->margin_bbs);
	    free(cfg->margin_bbs);
	    destroy_container(cfg->pmbbs);
	    free(cfg->pmbbs);
	}
	destroy_container(CFGs);
	free(CFGs);
}

static CFG * loadFuncCFG(char * fname) {
	OKF("Load CFG for %s",fname);

	/*pre step: load answers */
	map_void_t bb_branch_info;
	map_init(&bb_branch_info);
	FILE * f;
	u8 * fn = alloc_printf("%s/bb_branch_info/%s.bb_branch_info.txt", temp_dir, fname);
	if (!(f = fopen(fn, "r"))) {
		ck_free(fn);
		FATAL("No such file or directory: %s",fn);
	}
	u8 tmp[MAX_LINE];
	while (fgets(tmp, MAX_LINE, f)) {
		if(0==strcmp(tmp,""))continue;
		strtok(tmp,"|");//char * incr_id=strtok(tmp,"|");
		char * answer_str=strdup(strtok(NULL,"|"));//strdup is required as the string will be recycle
		char * key=strtok(NULL,"|");
		map_set(&bb_branch_info,key,answer_str);//
//		OKF("%s->%s",key,answer_str);
	}
//	map_iter_t iter = map_iter(&bb_branch_info);
//	const char *kk;
//	while ((kk = map_next(&bb_branch_info, &iter)))
//	{
//		char * v=(char *)*map_get(&bb_branch_info, kk);
//		OKF("%s->%s",kk,v);
//
//	}
	ck_free(fn);
	fclose(f);

	/*1. init vetex_index */
	fn = alloc_printf("%s/index/%s.node_index.txt",temp_dir, fname);

	if (!(f = fopen(fn, "r"))) {
		ck_free(fn);
		FATAL("No such file or directory: %s",fn);
	}
	CFG * cfg=(CFG *)malloc(sizeof(CFG));
	cfg->fname=alloc_printf("%s",fname);
	cfg->rid2node =(map_void_t *)malloc(sizeof(map_void_t));
	cfg->pmbbs=(Container *)malloc(sizeof(Container));
	init_container(cfg->pmbbs);
	cfg->margin_bbs=NULL;
	vertex_num=0;

	map_init(cfg->rid2node);
	while (fgets(tmp, MAX_LINE, f)) {
		char *rid_str=strtok(tmp,"|");
		int rid=atoi(rid_str);
		strtok(NULL,"|");//char * nid=strtok(NULL,"|");
		char * key_str=strtok(NULL,"|");

		char *answer_str=NULL;
		void **p=map_get(&bb_branch_info,key_str);
		if(p){
			answer_str=strdup((char*)*p);
			//FATAL("%s %s->%s",fname,key_str,(char*)*p);
		}
		Node * node=(Node *)malloc(sizeof(Node));
		char * bbname=strtok(key_str,";");
		if (strlen(bbname)==0)
			strcpy(node->bbname,"@");
		else{
			strcpy(node->bbname,bbname);
		}
		//if(!strcmp("ttgload.c:2712:12",bbname))FATAL("###########%s,rid=%d",bbname,rid);
		node->rid=rid;
		node->cov=0;
		node->distance=-1.0;
		node->out_degree=0;
		node->is_margin=0;
		node->is_margin_last_check=0;
		node->margin_history=0;
		node->branch_type=UNKNOWN;
		node->successors=NULL;
		node->invalid_positions=NULL;
		map_set(cfg->rid2node, rid_str, node);
		node->answer_str=answer_str;


		/*
		void **p=map_get(global_rid2node, rid_str);
		if(!p){
			map_set(global_rid2node, rid_str, node);
		}else if(DUL_RID==*p){//DUL_RID==*p
			map_void_t * fnames = (map_void_t *)* map_get(global_rid2fnames,rid_str);
			map_set(fnames, fname, NULL);
		}else{
			char * fname_pre= (char *)*p;
			map_void_t* fnames=(map_void_t *)malloc(sizeof(map_void_t));
			map_set(fnames, fname_pre, NULL);
			map_set(fnames, fname, NULL);
			map_set(global_rid2fnames, rid_str, fnames);
			map_set(global_rid2node, rid_str, DUL_RID);
		}*/

		vertex_num++;
	}
	if(vertex_num==0){
		return NULL;
	}
	ck_free(fn);
	fclose(f);

	map_deinit(&bb_branch_info);//deinit bb_branch_info


    /*2. init out_edge_index */
	fn = alloc_printf("%s/index/%s.out_edge_index.txt", temp_dir, fname);

	if (!(f = fopen(fn, "r"))) {
		ck_free(fn);
		FATAL("No such file or directory: %s",fn);
	}
	edge_num=0;
	while (fgets(tmp, MAX_LINE, f)) {

		char * first=strtok(tmp,",");
		char * second=strtok(NULL,",");
		int last=strlen(second)-1;
		second[last]=second[last]=='\n'?'\0':second[last];//strip the '\n'
		void **p = map_get(cfg->rid2node,first);
		if(!p){
			FATAL("Cannot find rid:%s in rid2node.", first);
		}
		Node* node=(Node*)*p;
		if(node->successors==NULL){
			node->successors=(map_int_t *)malloc(sizeof(map_int_t));
			map_init(node->successors);
		}

		if(!map_get(node->successors,second)){
			node->out_degree+=1;
		}//ingore muti-edges to same node
		map_set(node->successors,second,0);//cov:0
		edge_num++;
	}
	OKF("Total: %d out_edges.",edge_num);
	ck_free(fn);
	fclose(f);

	/*3. init reachable bbname list */
	fn = alloc_printf("%s/%s",temp_dir, "distance.cfg.txt");
	if (!(f = fopen(fn, "r"))) {
		ck_free(fn);
		FATAL("No such file or directory: %s",fn);
	}
	int rlist_num=0;
	while (fgets(tmp, MAX_LINE, f)) {
		char * file_and_line=strtok(tmp,",");
		if(!strstr(file_and_line,":")) continue;
		char * d_str=strtok(NULL,",");
		double d=atof(d_str);
		const char *key;
		map_iter_t iter = map_iter(cfg->rid2node);
		while ((key = map_next(cfg->rid2node, &iter)))
		{
		    void **p=map_get(cfg->rid2node, key);
		    if(!p) FATAL("rid2node contains NULL node");
			Node* node=(Node *)*p;
			if (strstr(node->bbname,file_and_line))
			{
				node->distance=d;
				if(node->out_degree>1){
					add_element(cfg->pmbbs,node);
				}
				rlist_num++;//break; //Don't break, because there may be vertexes with same bbname. TODO:verify and fix it
			}
		}
	}
	/*if(!strcmp(fname,"TT_Load_Glyph")){
	void **p=map_get(rid2node,"24289");
	FATAL("#########%f",((Node*)*p)->distance);}*/
	OKF("Total: %d reachable bbname.",rlist_num);
	ck_free(fn);
	fclose(f);
	cfg_loaded=1;
	return cfg;
}
static void loadCFG()
{
	u8 *fn = alloc_printf("%s/%s",temp_dir, "/distance.callgraph.txt");
	FILE * f;
	if (!(f = fopen(fn, "r"))) {
		ck_free(fn);
		FATAL("No such file or directory: %s",fn);

	}
	if(!CFGs){
		CFGs=(Container*)malloc(sizeof(Container));
		init_container(CFGs);
	}
	char line[MAX_LINE];
	while (fgets(line, MAX_LINE, f)) {
		char * fname=strtok(line,",");
		CFG * cfg = loadFuncCFG(fname);
		add_element(CFGs,cfg);
	}
	ck_free(fn);
	fclose(f);
}



/* prioritize Basic Blocks(idendified by random id(RID)) located at the margin
 * area of the covered code.
 */

static int update_margin_bbs(int len)
{

	int updated=0;
	margin_bb_count=0;

	for (int i=0;i<CFGs->cur_size;i++) {
		/*1. update coverage information and clean margin*/
		CFG * cfg=(CFG *)CFGs->elements[i];
		char *fname = cfg->fname;
		if(!cfg->rid2node) FATAL("CFG of %s() is empty. rid2node=(nil)",fname);
		map_void_t *rid2node = cfg->rid2node;
		const char *rid_str;
		map_iter_t node_iter = map_iter(&rid2node);
		while ((rid_str = map_next(rid2node, &node_iter))) {
			void **p=map_get(rid2node, rid_str);
			if(!p) FATAL("rid2node is broken, rid=%s,node=(nil)",rid_str);
			Node * node = (Node *)*p;
			if(!node->successors) continue;
			int start=node->rid;
			const char *end_str;
			map_iter_t succ_iter = map_iter(node->successors);
			while ((end_str = map_next(node->successors, &succ_iter))) {
				int end=atoi(end_str);
				if (trace_bits[(start>>1)^end]!=0xff)
				{
					if(trace_bits[(start>>1)^end] >(u8)(*map_get(node->successors,end_str))){
						//OKF("%d=>%d  ",(u8)*map_get(node->successors,end_str),trace_bits[(start>>1)^end]);
						map_set(node->successors,end_str,trace_bits[(start>>1)^end]);
						node->cov=1;
						if(!map_get(rid2node, end_str)){
							FATAL("Wierd,end_str=%s,fname=%s",end_str,cfg->fname);
						}
						((Node *)*map_get(rid2node, end_str))->cov=1;

//						//DEBUG CODE
//						OKF("=>%d  ",trace_bits[(start>>1)^end]);
//						char *cmd=alloc_printf("sed -i \"s/%d->%d.*/%d->%d[label=%u,color=Red];/g\" %s/index/%s.out_edge_index.dot\n",start,end,start,end,trace_bits[(start>>1)^end],temp_dir,fname);
//						system(cmd);
//						char * log_file_name=alloc_printf("%s/tem.txt", out_dir);
//						log2file_and_free(log_file_name,cmd);
//						char *cmd2=alloc_printf("dot -Tsvg %s/index/%s.out_edge_index.dot -o %s/index/%s.out_edge_index.svg",temp_dir,fname,temp_dir,fname);
//						system(cmd2);
//						ck_free(cmd2);
//						//ck_free(cmd);
					}
				}
			}
		}
		/*2 clean margin record*/
		if(!cfg->margin_bbs){
			cfg->margin_bbs=(Container*)malloc(sizeof(Container));
			init_container(cfg->margin_bbs);
		}else{
			destroy_container(cfg->margin_bbs);
			init_container(cfg->margin_bbs);
		}
		/*3. find and record margin basic blocks.*/
		Container * pmbbs = cfg->pmbbs;
		for(int j=0;j<pmbbs->cur_size;j++){
			Node * node = (Node*)pmbbs->elements[j];
			if(node->cov==1){
				node->is_margin=0;
				map_iter_t succ_iter = map_iter(node->successors);
				//for each successors of BB_start
				const char *end_str;
				while ((end_str = map_next(node->successors, &succ_iter))) {
					//Margin BB condition:
					//BB_start(cov:1)-[cov:0]->BB_end(distance>0)
					int cov=*map_get(node->successors,end_str);
					if (!cov && ((Node*)*map_get(rid2node,end_str))->distance>-0.0001)
					{
						add_element(cfg->margin_bbs,node);
						if(node->margin_history==0){
							if(node->distance<min_d && node->distance >-0.0001)
							{
								if(!strcmp(node->bbname,"ttgload.c:2712:12"))
								{
									//FATAL("ttgload.c:2712:12 distance=%f",node->distance);
								}
								min_d=node->distance;
								char key[32];
								sprintf(key,"%d",cur_trace_len);
								void **p=map_get(&trace2strategy, key);
								Strategy *s;
								if(!p){
								   s=(Strategy *)malloc(sizeof(Strategy));
								   s->record_list=NULL;
								   s->hit_cnt=0;
								   map_init(&s->record_map);
								   map_set(&trace2strategy, key, s);
								}
								remove_candidates();
								remove_values(&target_bb->value_list);
								remove_values(&target_bb->answer_list);
								target_bb->answer_focus=NULL;
								target_bb->node=node;
								target_bb->scanning_tasks=1;
								target_bb->solving_stage=SCAN;
								target_bb->max_len=len>target_bb->max_len?len:target_bb->max_len;
								target_bb->born_cycle=queue_cycle;
								strcpy(target_bb->function,fname);
								updated=1;
							}

//							//DEBUG CODE
//							u8 *fn = alloc_printf("%s/index/%s.out_edge_index.dot",temp_dir,fname);
//							FILE * f;
//							if (!(f = fopen(fn, "r+"))) {
//								ck_free(fn);
//								return;
//							}
//							fseek(f,-2L,SEEK_END);
//							u8* node_str=alloc_printf("\n%d [label=\"%d\",color=Blue ,shape=record];\n}",start,start);
//							fputs(node_str,f);
//							fclose(f);
//							ck_free(node_str);
//							ck_free(fn);
//							char *cmd=alloc_printf("dot -Tsvg %s/index/%s.out_edge_index.dot -o %s/index/%s.out_edge_index.svg",temp_dir,fname,temp_dir,fname);
//							system(cmd);
//							ck_free(cmd);
						}else{
							//margin still not solved
						}
						node->margin_history+=1;
						node->is_margin=1;
						margin_bb_count++;
						break;
					}
				}
			}
		}
	}
	return updated;
}
/* add by yangke end */
static inline char * get_description(int mut_code)
{
	switch (mut_code){
		  case 0:
			  return "Flip bit.";
			  break;
		  case 1:
			  return "Set byte interesting.";
			  break;
		  case 2:
			  return "Set word interesting.";
			  break;
		  case 3:
			  return "Set dword interesting.";
			  break;
		  case 4:
			  return "Randomly subtract from byte.";
			  break;
		  case 5:
			  return "Randomly add to byte.";
			  break;
		  case 6:
			  return "Randomly subtract from word, random endian.";
			  break;
		  case 7:
			  return "Randomly add to word, random endian.";
			  break;
		  case 8:
			  return "Randomly subtract from dword, random endian.";
			  break;
		  case 9:
			  return "Randomly add to dword, random endian.";
			  break;
		  case 10:
			  return "Just set a random byte to a random value.";
			  break;
		  case 11 ... 12:
		  	  return "Delete bytes.";
			  break;
		  case 13:
			  return "Clone bytes (75%) or insert a block of constant bytes (25%).";
			  break;
		  case 14:
			  return "Overwrite bytes with a randomly selected chunk (75%) or fixed bytes (25%).";
			  break;
		  case 15:
			  return "Overwrite bytes with an extra.";
			  break;
		  case 16:
			  return "Insert an extra.";
			  break;
		  default:
			  FATAL("UNKNOWN MUTATION CODE:%d",mut_code);
			  return "UNKNOWN MUTATION CODE:";
	}
}

static inline void print_mutation_table()
{
	u8 * log_file_name=alloc_printf("%s/valid_mut_log.txt", out_dir);
	int debug_fd = open(log_file_name, O_WRONLY | O_CREAT | O_APPEND, 0600);
	OKF("#####INTERESTING MUTATION TABLE#####");
	ck_write(debug_fd, "#####INTERESTING MUTATION TABLE#####\n", strlen("#####INTERESTING MUTATION TABLE#####\n"), log_file_name);
	const char * trace_len_str;

	map_iter_t iter0 = map_iter(&trace2strategy);

	while ((trace_len_str = map_next(&trace2strategy, &iter0))) {

		char * len_info=alloc_printf("len=%s\n",trace_len_str);
		ck_write(debug_fd,len_info,strlen(len_info),log_file_name);
		ck_free(len_info);
		Strategy* s=(Strategy *)*map_get(&trace2strategy, trace_len_str);
		for(Record * r=s->record_list;r;r=r->next){
			char rid_list_str[512];
			char *ptr=rid_list_str;
			for(hashset_itr_t iter = hashset_iterator(r->B);hashset_iterator_has_next(iter);hashset_iterator_next(iter))
			{
				Node *node =(Node *)hashset_iterator_value(iter);
				ptr+=sprintf(ptr,"%d,",node->rid);
			}

			char pos_list_str[512];
			ptr=pos_list_str;
			const char * pos_str;
			map_iter_t iter2 = map_iter(&r->P);
			while ((pos_str = map_next(&r->P, &iter2))) {
				ptr+=sprintf(ptr,"%s,",pos_str);
			}
			char * line =alloc_printf("rid group=%s,pos:%s\n",rid_list_str,pos_list_str);
			ck_write(debug_fd,line,strlen(line),log_file_name);
			ck_free(line);

			for(int i=0;i<MUT_NUM;i++)
			{
				if(r->M[i])
				{
					char mut_line[256];
					sprintf(mut_line,"%d,%s\n",i,get_description(i));
					ck_write(debug_fd,mut_line,strlen(mut_line),log_file_name);
				}
			}
		}
		ck_write(debug_fd,"------------------\n",strlen("------------------\n"),log_file_name);
	}
	close(debug_fd);
	ck_free(log_file_name);
}
/* add by yangke start */
static inline u8 update_hit_cnt()
{
	u8 ret=1;
	char key[32];
	sprintf(key,"%d",cur_trace_len);
	void **p=map_get(&trace2strategy, key);
	Strategy *s;
	if(!p){
	  /* create strategy */
	  s=(Strategy *)malloc(sizeof(Strategy));
	  s->record_list=NULL;
	  s->hit_cnt=0;
	  map_init(&s->record_map);
	  map_set(&trace2strategy, key, s);
	  /* calculate the average hit_cnt */
	  OKF("INSERT TO:trace_len_map max_trace_len:%d,cur_trace_len:%d",max_trace_len,cur_trace_len);
	  if(trace_classes==0){
		  avg_hit_cnt=0.0;
	  }
	  avg_hit_cnt=avg_hit_cnt*(trace_classes/(trace_classes+1.0))+1.0/(trace_classes+1.0);

	  //print_mutation_table();
	  trace_classes++;
	  ret=0;
	}else{
	  s=(Strategy *)*p;
	  s->hit_cnt++;
	  avg_hit_cnt=avg_hit_cnt+1.0/trace_classes;

	}
	OKF("avg_fuzz_cnt=%f,trace_cnt=%u",avg_hit_cnt,trace_classes);
	char * log_file_name=alloc_printf("%s/trace_len.txt", out_dir);
	char * info=alloc_printf("%s:%d\n",key,((Strategy *)*map_get(&trace2strategy,key))->hit_cnt);
	log2file_and_free(log_file_name,info);
	return ret;
}

static Strategy * create_strategy(char *key){
	Strategy *s=(Strategy *)malloc(sizeof(Strategy));
	s->record_list=NULL;
	s->hit_cnt=0;
	map_init(&s->record_map);
	map_set(&trace2strategy, key, s);//initialize strategy
	return  s;
}
static Strategy * get_strategy(int trace_len){
	char key[32];
	sprintf(key,"%d",trace_len);
	void **p=map_get(&trace2strategy, key);
	if(!p){
		return create_strategy(key);
	}else{
		return (Strategy *)(*p);
	}
}
static void setup_new_linear_search(int len,int trace_len){
	target_bb->scanning_tasks+=1;
	OKF("start linear search,target_bb->scanning_tasks=%d",target_bb->scanning_tasks);
	target_bb->max_len=len>target_bb->max_len?len:target_bb->max_len;
}
static void add_position(LinkListPosition * pos_list,int pos){
	LinkedPosition * p=(LinkedPosition *)malloc(sizeof(LinkedPosition));
	p->pos=pos;
	p->answer=NULL;
	p->is_field=0;
	p->fuzz_cnt=0;
	p->next=pos_list->head;
	pos_list->head=p;
	for(int i=0;i<FMAP_LEN;i++){
		p->fmap[i].input=0;
		p->fmap[i].output=0;
		p->fmap[i].valid=0;
	}
	pos_list->len++;
}


static void add_candidate(struct queue_entry * entry, u64 v){
	Candidate * c=(Candidate *)malloc(sizeof(Candidate));
	c->entry=entry;
	c->fuzz_pos=0;
	c->base_value=v;
	c->pos_focus=NULL;
	c->eff_pos_list.head=NULL;
	c->eff_pos_list.len=0;
	c->next=NULL;
	if(!target_bb->c_list){
	  target_bb->c_list=c;
	  c->next=NULL;
	}else{
	  FATAL("This should not happen!!");
	  c->next=target_bb->c_list;
	  target_bb->c_list=c;
	}
	//note that target_bb->c_focus is not set yet!
	target_bb->c_focus=c;
	target_bb->c_list_len++;
	if(target_bb->c_list_len>1){
		FATAL("Assert c_list_len<=1 failed!");
	}
}
static inline void insert_value(LinkListInteger * v_list,u64 v){
	LinkedInteger * new_v =(LinkedInteger *)malloc(sizeof(LinkedInteger));
	new_v->v=v;
	new_v->next=v_list->head;
	v_list->head=new_v;
	v_list->len++;
}
static inline void remove_values(LinkListInteger * v_list){
	LinkedInteger * i;
    while(v_list->head){
    	i=v_list->head;
    	v_list->head=v_list->head->next;
    	free(i);
    }
    v_list->len=0;
}
static inline void display_value_list(LinkListInteger *v_list){
	if(!v_list) return;
	LinkedInteger *i=v_list->head;
	char * s=NULL;
	while(i){
		if(!s){
			s=alloc_printf("%llx",i->v);
		}else{
			char* t=alloc_printf("%s,%llx",s,i->v);
			ck_free(s);
			s=t;
		}
		i=i->next;
	}
	OKF("value_list:{%s}",s);
	ck_free(s);
}
static inline void display_fmap(LinkedPosition * p){
	if(!p)return;
	char * s=NULL;
	for(int i=0;i<FMAP_LEN;i++){
		if(!s){
			s=alloc_printf("(%x,%llx,%x)",p->fmap[i].input,p->fmap[i].output,p->fmap[i].valid);
		}else{
			char* t=alloc_printf("%s,(%x,%llx,%x)",s,p->fmap[i].input,p->fmap[i].output,p->fmap[i].valid);
			ck_free(s);
			s=t;
		}
	}
	OKF("[%d] FMAP:{%s}",p->pos,s);
}
static void delete_position(LinkListPosition * pos_list,LinkedPosition *p){
	if(!pos_list->head||!p) return;
	if(pos_list->head==p){
		pos_list->head=pos_list->head->next;
		if(p->answer){
			free(p->answer);
		}
		free(p);
		pos_list->len--;
	}else{
		LinkedPosition * position=pos_list->head;
		while(position->next!=p){
			position=position->next;
		}
		if(position->next==p){
			position->next=p->next;
			if(p->answer){
				free(p->answer);
			}
			free(p);
			pos_list->len--;
		}
	}
}
static void remove_positions(LinkListPosition * pos_list){
	LinkedPosition * p;
	while(pos_list->head){
		p=pos_list->head;
		pos_list->head=pos_list->head->next;
		if(p->answer){
			free(p->answer);
		}
		free(p);
	}
}
static inline void remove_candidates(){
	Candidate * c;
	while(target_bb->c_list){
		c=target_bb->c_list;
		target_bb->c_list=target_bb->c_list->next;
		c->pos_focus=NULL;
		remove_positions(&c->eff_pos_list);
		free(c);
	}
	target_bb->c_list_len=0;
	target_bb->c_focus=NULL;
}



static inline int unseen(LinkListInteger *v_list, u64 v){
	for(LinkedInteger * i=v_list->head;i!=NULL;i=i->next){
		if(i->v==v){
			return 0;
		}
	}
	insert_value(v_list, v);
	return 1;
}
static inline int is_output_unique(LinkedPosition *p){
	int valid_cnt=0;
	for(int i=0;i<FMAP_LEN;i++){
		if(p->fmap[i].valid){
			valid_cnt++;
			for(int j=i+1;j<FMAP_LEN;j++){
				if(p->fmap[i].output==p->fmap[j].output && p->fmap[i].valid && p->fmap[j].valid){
					OKF("!!3");
					return 0;
				}
			}
		}
	}
	if(valid_cnt>=FMAP_LEN-1){
		OKF("!!1");
		return 1;
	}else{
		OKF("!!2");
		return 0;
	}
}


/* add by yangke end */

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {
  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;
  u8  add_it=0;
  u64* cur = (u64*)(trace_bits+MAP_SIZE+16);
  OKF("####");
  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
    /* add by yangke start */
	hnb = has_new_bits(virgin_bits);
	if (!cfg_loaded) loadCFG();
	if (target_bb->node) mut_prior_mode=1;//open if we can detect target
	if (queue_cur->exec_path_len==0){
		queue_cur->exec_path_len=cur_trace_len;//refer has_new_bits() for its calculation
		if(update_margin_bbs(len)){
			add_candidate(queue_cur,cur[target_bb->node->rid]);
			//set base_value for candidate under focus
		}
//		Node * node_list[margin_bb_count];
//		has_new_var_bits(virgin_var_bits,node_list);

		return 0;//TODO:check whether this will discard new pathes
	}

	if(target_bb->node && (0xffffffffffffffff!=cur[target_bb->node->rid])){//trigger target
		switch (target_bb->node->branch_type)
		{
			case UNKNOWN:
				if(target_bb->c_focus){
					if(target_bb->scanning_tasks>0){//&& queue_cur->exec_path_len==cur_trace_len&& target_bb->c_focus
						OKF("base/cur:%llx/%llx",target_bb->c_focus->base_value,cur[target_bb->node->rid]);
						if(target_bb->c_focus->base_value!=cur[target_bb->node->rid]){//during scanning we find a different value
							add_position(&target_bb->c_focus->eff_pos_list,target_bb->c_focus->fuzz_pos-1);//signal the type check after finish linear search.
						}
					}else if(target_bb->solving_stage==JUDGE){//&& queue_cur->exec_path_len==cur_trace_len
						LinkedPosition *p=target_bb->c_focus->pos_focus;
						u8  * t=(u8 *)mem;
						u8 answer=(u8)(t[p->pos]+cur[target_bb->node->rid]);
						OKF("answer:0x%x=%x+%llx,%d,cur_trace_len=%d",answer,t[p->pos],cur[target_bb->node->rid],queue_cur->exec_path_len,cur_trace_len);
						if(p->fuzz_cnt==1){
							p->answer=(u8*)malloc(sizeof(u8));
							*(p->answer)=answer;
						}else if(p->fuzz_cnt>1 && p->answer && *(p->answer)!=answer){
							free(p->answer);
							p->answer=NULL;
						}
						p->fmap[p->fuzz_cnt-1].output=cur[target_bb->node->rid];
						p->fmap[p->fuzz_cnt-1].valid=1;
						if(p->fuzz_cnt==FMAP_LEN){
							if(is_output_unique(p)){
								OKF("%x,%llx",t[p->pos],(u64)cur[target_bb->node->rid]);
								OKF("GUESS VALUE:0x%llx",t[p->pos]+cur[target_bb->node->rid]);
								OKF("ANSL:%s",target_bb->node->answer_str);
								target_bb->node->branch_type=FIELD_BASED;
								p->is_field=1;
								cleanup_value_changing_mutation_record();
								Strategy *s=get_strategy(queue_cur->exec_path_len);
								record_value_changing_mutation(&target_bb->node,1,s);
							}
							//else p->is_field=0 signal dispatch_random()
						}
					}
				}
				break;
			case FIELD_BASED:
				if(cycles_wo_finds >=target_bb->max_len*10){
					target_bb->node->branch_type=STATE_BASED;
				}
				break;
			case STATE_BASED:
				if(cur_trace_len>=queue_cur->exec_path_len){
					  Node * node_list[margin_bb_count];
					  int cnt=has_new_var_bits(virgin_var_bits,node_list);
					  if(cnt){
						  Strategy *s=get_strategy(queue_cur->exec_path_len);
						  record_value_changing_mutation(node_list,cnt,s);
					  }
					  if(cur_trace_len>queue_cur->exec_path_len){
						  //TODO:reserve this seed
					  }
				}
		}
	}
    if (!hnb) {
    	if (crash_mode) total_crashes++;
    	return 0;
    }else{//new coverage fond
    	//examin mutations that contribute to this new coverage
    	if(target_bb->node && target_bb->node->branch_type==STATE_BASED && cur_trace_len<queue_cur->exec_path_len){

		}else{
			for(int i=0;i<MUT_NUM;i++)
			{
				if(one_fuzz_mut_cnt[i]>0){
					mut_score[i]+=1;//one_fuzz_mut_cnt[i];
				}
				//OKF("%02d,%d|%d|[%d]%s",i,mut_score[i],mut_cnt[i],tmp_mut_cnt[i],get_description(i));
			}
		}

    	if (!cfg_loaded)
			loadCFG();
		int updated=update_margin_bbs(len);
		get_strategy(cur_trace_len);
		if(updated){
			add_it=1;
		}else if (target_bb->node && target_bb->node->branch_type!=STATE_BASED){
			//if(target_bb->node->branch_type==FIELD_BASED)return 0;
			if(queue_cycle > target_bb->born_cycle+target_bb->max_len*14){
				target_bb->node->branch_type=STATE_BASED;
				remove_candidates();
				remove_values(&target_bb->value_list);
				remove_values(&target_bb->answer_list);
				FATAL("target rid=%d,%s is a state based target",target_bb->node->rid,target_bb->node->bbname);
			}
		}

		if ((target_bb->node && target_bb->node->branch_type==STATE_BASED)||updated){
			cleanup_value_changing_mutation_record();
			WARNF("clean UP!");
		}
    }
    /* add by yangke end */
#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* add by yangke start */
    if(add_it)
    {
  	  add_candidate(queue_top,cur[target_bb->node->rid]);
    }
    /* add by yangke start */

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

//      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
//                        unique_crashes, kill_signal, describe_op(0));
      fn = alloc_printf("%s/crashes/id:%06u,%llu,%f,%s", out_dir, queued_paths,
          		          get_cur_time() - start_time, cur_distance,
                            describe_op(hnb));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;
      /* add by yangke start */
      OKF("First Crash is Achieved! Exit now!");
      u8 * statistic_file_name=alloc_printf("%s/statistics", out_dir);
      u8 * info=alloc_printf("mon/rand mut_times:%d|%d,%0.2f,win_times,%d|%d\n",monitor_mut,random_mut,(float)monitor_mut/(float)random_mut,monitor_win,random_win);
      int statistic_file_fd = open(statistic_file_name, O_WRONLY | O_CREAT | O_APPEND, 0600);
      if (statistic_file_fd < 0) PFATAL("Unable to create '%s'", statistic_file_name);
      ck_write(statistic_file_fd, info, strlen(info), statistic_file_name);
      ck_write(statistic_file_fd, mem, len, statistic_file_name);
      ck_write(statistic_file_fd, "\n", 1, statistic_file_name);
      close(statistic_file_fd);
      ck_free(statistic_file_name);
      ck_free(info);
      fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0) PFATAL("Unable to create '%s'", fn);
      ck_write(fd, mem, len, fn);
      close(fd);
      ck_free(fn);
      //clean up
      fclose(plot_file);
	  destroy_queue();
	  destroy_extras();
	  destroy_all_cfg();
	  destroy_target();
	  destroy_records();
	  ck_free(target_path);
	  ck_free(sync_id);
      alloc_report();
      exit(0);
      /* add by yangke end */

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off) return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths) ret = 0;
  return ret;

}


/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout   : ");
  if (!off) return;

  ret = atoi(off + 17);
  if (ret <= 4) return;

  exec_tmout = ret;
  timeout_given = 3;

}


/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double last_bcvg, last_stab, last_eps;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability  = last_stab;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps  = eps;
  }

  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %u\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n"
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "command_line      : %s\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_favored, queued_discovered, queued_imported,
             max_depth, current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, stability, bitmap_cvg, unique_crashes,
             unique_hangs, last_path_time / 1000, last_crash_time / 1000,
             last_hang_time / 1000, total_execs - last_crash_execs,
             exec_tmout, use_banner, orig_cmdline);
             /* ignore errors */

  fclose(f);

}


/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;

  prev_qp  = queued_paths;
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* ignore errors */

  fflush(plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' && (!prefix ||
        !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void) {

  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);

  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f) {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in '%s'", out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume) {

    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  fn = alloc_printf("%s/.synced", out_dir);
  if (delete_files(fn, NULL)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  if (!in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) {
    fn  = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


static void check_term_size(void);


/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes) 
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
 
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 80x25.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (cycles_wo_finds < 25 || min_wo_finds < 30) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
      in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 
          100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP 
       " favored paths : " cRST "%-22s " bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         "   new crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         " total crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
       "  imported : " cRST "%-10s " bSTG bV "\n", tmp,
       sync_id ? DI(queued_imported) : (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp);

  if (t_bytes) sprintf(tmp, "%0.02f%%", stab_ratio);
    else strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) 
       ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20))
       ? cMGN : cRST), tmp);

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
            blocks_eff_total);

    strcat(tmp, tmp2);

  }

  SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
       bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, 
           MIN(cpu_aff, 999), cpu_color,
           MIN(cur_utilization, 999));

    } else {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
           cpu_color, MIN(cur_utilization, 999));
 
   }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000)) 
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000) havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
    else exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  } else if (timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");

}


/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

} 


/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (q->len < 5) return 0;

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv, exec_tmout);
      trim_execs++;

      if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2  = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(clean_trace, trace_bits, MAP_SIZE);

        }

      } else remove_pos += remove_len;

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();
      stage_cur++;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}


/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  if (post_handler) {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) rlim = 1;

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  u64 cur_ms = get_cur_time();
  u64 t = (cur_ms - start_time) / 1000;
  double progress_to_tx = ((double) t) / ((double) t_x * 60.0);

  double T;

  //TODO Substitute functions of exp and log with faster bitwise operations on integers
  switch (cooling_schedule) {
    case SAN_EXP:

      T = 1.0 / pow(20.0, progress_to_tx);

      break;

    case SAN_LOG:

      // alpha = 2 and exp(19/2) - 1 = 13358.7268297
      T = 1.0 / (1.0 + 2.0 * log(1.0 + progress_to_tx * 13358.7268297));

      break;

    case SAN_LIN:

      T = 1.0 / (1.0 + 19.0 * progress_to_tx);

      break;

    case SAN_QUAD:

      T = 1.0 / (1.0 + 19.0 * pow(progress_to_tx, 2));

      break;

    default:
      PFATAL ("Unkown Power Schedule for Directed Fuzzing");
  }

  double power_factor = 1.0;
  if (q->distance > 0) {

    double normalized_d = q->distance;
    if (max_distance != min_distance)
      normalized_d = (q->distance - min_distance) / (max_distance - min_distance);

    if (normalized_d >= 0) {

        double p = (1.0 - normalized_d) * (1.0 - T) + 0.5 * T;
        power_factor = pow(2.0, 2.0 * (double) log2(MAX_FACTOR) * (p - 0.5));

    }// else WARNF ("Normalized distance negative: %f", normalized_d);

  }

  perf_score *= power_factor;

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  /* AFLGO-DEBUGGING */
  // fprintf(stderr, "[Time %llu] q->distance: %4lf, max_distance: %4lf min_distance: %4lf, T: %4.3lf, power_factor: %4.3lf, adjusted perf_score: %4d\n", t, q->distance, max_distance, min_distance, T, power_factor, perf_score);

  return perf_score;

}


/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}


/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}


/* Last but not least, a similar helper to see if insertion of an 
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;

  }

  return 0;

}

/* add by yangke start */
static inline void init_value_changing_mutation_record()
{
	total_mut_cnt=0;
	total_monitored_mut_cnt=0;
	for(int i=0;i<MUT_NUM;i++)
	{
		mut_cnt[i]=0;
	}
	map_init(&trace2strategy);
}
static inline void init_mutation_score()
{
	for(int i=0;i<MUT_NUM;i++)
	{
		mut_score[i]=0;
	}
}
static inline void cleanup_value_changing_mutation_record()
{
	const char *key;
	map_iter_t iter = map_iter(&trace2strategy);
	while ((key = map_next(&trace2strategy, &iter))) {
		Strategy * s=(Strategy *) *map_get(&trace2strategy, key);
		destroy_template_strategy(s);
	}
	if(value_changing_mutation_record_initialized)
		map_deinit(&trace2strategy);
	map_init(&trace2strategy);
	for(int i=0;i<MUT_NUM;i++)
	{
		mut_cnt[i]=0;
	}
}

static inline void cleanup_possible_value_changing_mutation_record()
{

	if(!tmp_pos_map_initialized){
		for(int i=0;i<MUT_NUM;i++)
		{
			map_init(&tmp_pos_map[i]);
		}
		tmp_pos_map_initialized=1;
	}else{
		for(int i=0;i<MUT_NUM;i++)
		{
			tmp_mut_cnt[i]=0;
			map_deinit(&tmp_pos_map[i]);
			map_init(&tmp_pos_map[i]);
		}
	}
}
static inline void cleanup_mutation_record()
{
	for(int i=0;i<MUT_NUM;i++)
	{
		one_fuzz_mut_cnt[i]=0;
	}
}

static int chcnt=0;
static void check_record(Strategy * s,char * mark)//all values in record_map must be records in record_list
{
	return;//currently disabled
	chcnt++;

	u8 * log_file_name=alloc_printf("%s/check_log.txt", out_dir);
	int debug_fd = open(log_file_name, O_WRONLY | O_CREAT | O_APPEND, 0600);
	char * info=alloc_printf("=----------%s----------=\n",mark);
	OKF("=----------%s----------=",mark);
	ck_write(debug_fd, info, strlen(info), log_file_name);
	ck_free(info);

	const char *key;
	map_iter_t iter = map_iter(&record_map);
	while ((key = map_next(&s->record_map, &iter))) {
		Record *cur_r=*(Record**)map_get(&s->record_map, key);

		OKF("key=%s,cur_r=%p",key,cur_r);

		Node * node;
		sscanf(key, "%p", &node);
		OKF("Converted key=%p",node);
		if(!hashset_is_member(cur_r->B,(void *)(node)))
		{
			FATAL("A This should not happen!");
		}

		char rid_list_str[256];
		char *ptr=rid_list_str;

		//int flag=0;
		for(hashset_itr_t iter = hashset_iterator(cur_r->B);hashset_iterator_has_next(iter);hashset_iterator_next(iter))
		{
			Node *node =(Node *)hashset_iterator_value(iter);
			//if(rid==atoi(key)){
			//	flag=1;
			//}
			ptr+=sprintf(ptr,"%d,",node->rid);
			//OKF("capacity:%lu",iter->set->capacity);
		}
//		if(!flag){
//			FATAL("B This should not happen!");
//		}
		info=alloc_printf("%d -> %p,%s\n", ((Node*)node)->rid, cur_r,rid_list_str);
		OKF("%d -> %p,%s", ((Node*)node)->rid, cur_r,rid_list_str);
		ck_write(debug_fd, info, strlen(info), log_file_name);
		ck_free(info);

		Record * it_r;
		for(it_r=s->record_list;it_r!=NULL&&it_r!=cur_r;it_r=it_r->next){
			map_iter_t pos_iter = map_iter(&it_r->P);
			const char *pos=NULL;
			int flag=0;
			while ((pos = map_next(&it_r->P, &pos_iter))) {
				flag=1;
			}
			if(!flag) FATAL("r->P is empty!");
		}
		if(it_r==NULL&&s->record_list!=NULL)FATAL("(%d) %s Not in record_list %d -> %p",chcnt,info,((Node*)node)->rid,cur_r);
	}
	close(debug_fd);
	ck_free(log_file_name);
}


/*
 * This function may change record_list
 * if "to" or "from" not in record_list, it will cause SIGSEGV
 * all value in record_map must be in record_list
 * You can use "check_record();" to check the completenese when debugging
 */
static inline void  merge_record(Record* to, Record* from,Strategy *s)
{
	if(!s->record_list||!to||!from||to==from){
		FATAL("EROOR record_list=%p,from=%p,to=%p",s->record_list,to,from);
	}
//	OKF("before");
//	for(Record *t=record_list;t!=NULL;t=t->next){
//		OKF("%p->",t);
//	}
	if(s->record_list!=to)
	{
		Record* prev;
		for(prev=s->record_list;prev!=NULL&&prev->next!=to;prev=prev->next);//SIGSEGV if from not in record_list
		if(prev==NULL)FATAL("Not in record_list to=%p",from);
	}
	if(s->record_list==from)
	{
		s->record_list=s->record_list->next;
	}else{
		Record* prev;
		for(prev=s->record_list;prev!=NULL&&prev->next!=from;prev=prev->next);//SIGSEGV if from not in record_list
		if(prev==NULL)FATAL("Not in record_list from=%p",from);
		prev->next=from->next;
	}
//	OKF("after");
//	for(Record *t=record_list;t!=NULL;t=t->next){
//			OKF("%p->",t);
//		}

	//Merge distances
	int to_num=hashset_num_items(to->B);
	int from_num=hashset_num_items(from->B);
	to->distance=(from_num*from->distance+to_num*to->distance)/(from_num+to_num);


	//Merge Branches
	for(hashset_itr_t iter = hashset_iterator(from->B);hashset_iterator_has_next(iter);hashset_iterator_next(iter))
	{
		Node * node=(Node *)hashset_iterator_value(iter);
		if(hashset_is_member(to->B,node)){
			FATAL("ERROR:The joint of record:%p and record %p contains %d, is not empty!",to,from,node->rid);
		}
		hashset_add(to->B, node);
		char node_ptr_str[32];//OKF("merge:%d",(int)(size_t)rid);
		sprintf(node_ptr_str,"%p",node);
		map_set(&s->record_map, node_ptr_str, to);
//		char ss2[16];
//		strcpy(ss2,rid_str);
//		void **p=map_get(&record_map,ss2);
//		if(!p||*p!=to){
//			FATAL("Key mismatch!!!");
//		}
	}
	check_record(s, "A");
	//Merge Muations
	for(int i=0;i<MUT_NUM;i++)
	{
		if(from->M[i]>0)
		{
			to->M[i]+=from->M[i];
		}
	}
	//Merge Positions
	map_iter_t pos_iter = map_iter(&from->P);
	const char *pos=NULL;
	while ((pos = map_next(&from->P, &pos_iter))) {
		int * cnt_to=map_get(&to->P, pos);
		int * cnt_from=map_get(&from->P, pos);
		if(!cnt_from)FATAL("Weird ERROR!");
		if(cnt_to)
		{
			map_set(&to->P, pos, *cnt_to+*cnt_from);
		}else{
			map_set(&to->P, pos, *cnt_from);
		}
	}
	check_record(s, "B");
	//destroy_record(from)
	hashset_destroy(from->B);
	map_deinit(&from->P);
	from->next=NULL;//clear memory
	free(from);
}

static inline void  record_value_changing_mutation(Node * node_list[],int size,Strategy *s)
{

	{
		for(int i=0;i<MUT_NUM;i++)
		{
			if(tmp_mut_cnt[i]>0 && i==10)
			{
				const char *pos_str;
				map_iter_t iter = map_iter(&tmp_pos_map[i]);
				char * pos_list_str=NULL;
				while ((pos_str = map_next(&tmp_pos_map[i], &iter))) {
					int pos_cnt=*map_get(&tmp_pos_map[i], pos_str);
					int hex_pos=atoi(pos_str);
					OKF("pos:0x%x",hex_pos);
					if(!pos_list_str){
						pos_list_str=alloc_printf("%x[%d]",hex_pos,pos_cnt);
					}else{
						char *temp_str=pos_list_str;
						pos_list_str=alloc_printf("%s,%x[%d]",temp_str,hex_pos,pos_cnt);
						ck_free(temp_str);
					}
				}
				OKF("%d: %s",i,pos_list_str);
			}
		}
	}

	if(size<=0){
		FATAL("ridlist size must >0, cur:%d",size);
	}
	Record * tmp_r=NULL;
	for(int i=0;i<size;i++)
	{
		char node_ptr_str[32];
		sprintf(node_ptr_str,"%p",node_list[i]);
		void ** p=map_get(&s->record_map, node_ptr_str);
		if(p){
			Record *cur_r=*p;
			if(!tmp_r){
				tmp_r=cur_r;
			}
			if(cur_r!=tmp_r){
				check_record(s, "C");
				merge_record((Record*)tmp_r,(Record*)cur_r,s);
				check_record(s, "D");
			}
		}
	}
	if(tmp_r){//insert to the merged tmp_r
		Record * r=tmp_r;
		check_record(s,"E");
		int origin_num=hashset_num_items(r->B);
		int disjoint_sum=0;
		int disjoint_cnt=0;
		for(int i=0;i<size;i++){
			if(!hashset_is_member(r->B,node_list[i])){
				hashset_add(r->B,node_list[i]);
				char node_ptr_str[32];
				sprintf(node_ptr_str,"%p",node_list[i]);
				map_set(&s->record_map, node_ptr_str, r);

				double temp_distance;
				temp_distance=node_list[i]->distance;
				/*char ptr_str[32];
				sprintf(ptr_str,"%p",node_list[i]);
				void **p=map_get(&scc_indicators,ptr_str);
				if(p){
					Node * node=(Node*)*p;
					if(node->distance<0)
					{
						FATAL("BB1(%d,%s)-> BB2(node_list[%d],%d,%s), BB1 is  Unreachable"
								"Please check the `node_list[]` and `scc_indicators`.",
								node->rid,node->bbname,i,node_list[i]->rid,node_list[i]->bbname);
					}
					temp_distance=node->distance;
				}else if(node_list[i]->distance<0){
					FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
				}else{
					temp_distance=node_list[i]->distance;
				}*//*
				if(target_bb->node && target_bb->scanning_tasks<=0 && target_bb->node->branch_type==2){
					//handle the loop out indicator
					char ptr_str[32];
					sprintf(ptr_str,"%p",node_list[i]);
					void **p=map_get(&scc_indicators,ptr_str);
					if(!p){
						FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
					}
					Node * node=(Node*)*p;
					if(node->distance<0)
					{
						FATAL("BB1(%d,%s)-> BB2(node_list[%d],%d,%s), BB1 is  Unreachable"
								"Please check the `node_list[]` and `scc_indicators`.",
								node->rid,node->bbname,i,node_list[i]->rid,node_list[i]->bbname);
					}
					temp_distance=node->distance;
				}else if(node_list[i]->distance<0){
					FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
				}else{
					temp_distance=node_list[i]->distance;
				}*/
				disjoint_sum+=temp_distance;
				disjoint_cnt++;
			}
		}
		r->distance=(r->distance*origin_num+disjoint_sum)/(origin_num+disjoint_cnt);
		if(r->distance-0.0<0.0001){
			FATAL("Illegal Zero Distance3! r->distance=%f",r->distance);
		}
		if(r->distance<min_gd){
			min_gd=r->distance;
		}
		if(r->distance>max_gd){
			max_gd=r->distance;
		}
		char * pos_list_str=NULL;
		for(int i=0;i<MUT_NUM;i++)
		{
			if(tmp_mut_cnt[i]>0)
			{
				r->M[i]+=tmp_mut_cnt[i];
				mut_cnt[i]+=tmp_mut_cnt[i];
				const char *pos_str;
				map_iter_t iter = map_iter(&tmp_pos_map[i]);
				while ((pos_str = map_next(&tmp_pos_map[i], &iter))) {
				    int pos_cnt=*map_get(&tmp_pos_map[i], pos_str);
				    int hex_pos=atoi(pos_str);
				    if(!pos_list_str){
				    	pos_list_str=alloc_printf("%x[%d]",hex_pos,pos_cnt);
				    }else{
				    	char *temp_str=pos_list_str;
				    	pos_list_str=alloc_printf("%s,%x[%d]",temp_str,hex_pos,pos_cnt);
				    	ck_free(temp_str);
				    }
					int *cnt=map_get(&r->P, pos_str);
					if(cnt)
					{
						map_set(&r->P, pos_str,*cnt+pos_cnt);
					}else{
						map_set(&r->P, pos_str,pos_cnt);
					}
				}
			}
		}
		char * info = alloc_printf("record-poslist:%s\n",pos_list_str);
		OKF("%s",info);
		if(pos_list_str){
			ck_free(pos_list_str);
		}
		char * log_file_name=alloc_printf("%s/value_affected_branch.txt", out_dir);
		log2file_and_free(log_file_name,info);
		//OKF("poslist:%s",pos_list_str);
		check_record(s, "F");
	}else{//create new record
		check_record(s, "G");
		Record * r=(Record *)malloc(sizeof(Record));
		r->B=hashset_create();
		r->next=NULL;
		double sum=0.0;
		for(int i=0;i<size;i++)
		{
			hashset_add(r->B,node_list[i]);
			char node_ptr_str[32];
			sprintf(node_ptr_str,"%p",node_list[i]);
			map_set(&s->record_map, node_ptr_str, r);

			double temp_distance;
			temp_distance=node_list[i]->distance;
			/*char ptr_str[32];
			sprintf(ptr_str,"%p",node_list[i]);
			void **p=map_get(&scc_indicators,ptr_str);
			if(p){
				Node * node=(Node*)*p;
				if(node->distance<0)
				{
					FATAL("BB1(%d,%s)-> BB2(node_list[%d],%d,%s), BB1 is  Unreachable"
							"Please check the `node_list[]` and `scc_indicators`.",
							node->rid,node->bbname,i,node_list[i]->rid,node_list[i]->bbname);
				}
				temp_distance=node->distance;
			}else if(node_list[i]->distance<0){
				FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
			}else{
				temp_distance=node_list[i]->distance;
			}*//*
			if(target_bb->node && target_bb->scanning_tasks<=0 && target_bb->node->branch_type==2){
				char ptr_str[32];
				sprintf(ptr_str,"%p",node_list[i]);
				void **p=map_get(&scc_indicators,ptr_str);
				if(!p){
					FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
				}
				Node * node=(Node*)*p;
				if(node->distance<0)
				{
					FATAL("BB1(%d,%s)-> BB2(node_list[%d],%d,%s), BB1 is  Unreachable"
							"Please check the `node_list[]` and `scc_indicators`.",
							node->rid,node->bbname,i,node_list[i]->rid,node_list[i]->bbname);
				}
				temp_distance=node->distance;
			}else if(node_list[i]->distance<0){
				FATAL("Unreachable BB rid:%d,bbname:%s",node_list[i]->rid,node_list[i]->bbname);
			}else{
				temp_distance=node_list[i]->distance;
			}*/
			sum+=temp_distance;
		}
		r->distance=sum/size;
		if(r->distance-0.0<0.0001){
			FATAL("Illegal Zero Distance2! r->distance=%f",r->distance);
		}
		if(r->distance<min_gd){
			min_gd=r->distance;
		}
		if(r->distance>max_gd){
			max_gd=r->distance;
		}
		map_init(&(r->P));
		memset(r->M,0,sizeof(int)*17);
		char * pos_list_str=NULL;
		for(int i=0;i<MUT_NUM;i++)
		{
			if(tmp_mut_cnt[i]>0)
			{
				r->M[i]+=tmp_mut_cnt[i];
				mut_cnt[i]+=tmp_mut_cnt[i];
				const char *pos_str;
				map_iter_t iter = map_iter(&tmp_pos_map[i]);
				while ((pos_str = map_next(&tmp_pos_map[i], &iter))) {
					int pos_cnt=*map_get(&tmp_pos_map[i], pos_str);
					int hex_pos=atoi(pos_str);
					OKF("pos:0x%x",hex_pos);
					if(!pos_list_str){
						pos_list_str=alloc_printf("%x[%d]",hex_pos,pos_cnt);
					}else{
						char *temp_str=pos_list_str;
						pos_list_str=alloc_printf("%s,%x[%d]",temp_str,hex_pos,pos_cnt);
						ck_free(temp_str);
					}
					map_set(&r->P, pos_str, pos_cnt);
				}
			}
		}
		char * info = alloc_printf("record-poslist:%s\n",pos_list_str);
		if(pos_list_str){
			ck_free(pos_list_str);
		}
		char * log_file_name=alloc_printf("%s/value_affected_branch.txt", out_dir);
		log2file_and_free(log_file_name,info);
		//OKF("poslist:%s",pos_list_str);
		if(s->record_list==NULL){
			s->record_list=r;
		}else{
			r->next=s->record_list;
			s->record_list=r;
		}
		check_record(s, "I");
	}

	//print_mutation_table(-1);
	/*
	u8 * log_file_name=alloc_printf("%s/records_log.txt", out_dir);
	int debug_fd = open(log_file_name, O_WRONLY | O_CREAT | O_APPEND, 0600);
	int group_cnt=0;
	for(Record * r=record_list;r!=NULL;r=r->next,group_cnt++){
		char str[256];
		char *ptr=str;
		for(hashset_itr_t iter = hashset_iterator(r->B);hashset_iterator_has_next(iter);hashset_iterator_next(iter)){
			int rid=(int)(size_t)hashset_iterator_value(iter);
			int len=sprintf(ptr,"%d,",rid);
			if(len<=0)FATAL("ERROR printing rids");
			ptr+=len;
			if(ptr>=str+256)FATAL("Overflow when printing rids");
		}
		char info[300];
		sprintf(info,"Group[%d]:%s,%f",group_cnt,str,r->distance);
		OKF("%s",info);
		ck_write(debug_fd, info, strlen(info), log_file_name);
	}
	close(debug_fd);
	ck_free(log_file_name);*/
	//OKF("Margin BB Groups:%d",groups);
}
static inline void record_possible_value_changing_mutation(int index, int pos)
{
	if(index >= MUT_NUM){
		//WARNF("mut[index=%d][pos=%d]+=1; //afl-fuzz.c:5370",index,pos);
		//WARNF("HEY! YANGKE! Mutation index(=%d) out of bound(MUT_NUM=%d)!",index,MUT_NUM);
	}else if(pos >= MAX_MUT_POS){
		//WARNF("mut[index=%d][pos=%d]+=1; //afl-fuzz.c:5373",index,pos);
		//WARNF("HEY! YANGKE! Mutation pos(=%d) out of bound(MAX_MUT_POS=%d)!",pos,MAX_MUT_POS);
	}else {
		char * pos_str=alloc_printf("%d",pos);
		int * cur_cnt=map_get(&tmp_pos_map[index],pos_str);
		if(cur_cnt){
			map_set(&tmp_pos_map[index],pos_str,*cur_cnt+1);
		}else{
			map_set(&tmp_pos_map[index],pos_str,1);
		}
		ck_free(pos_str);
		tmp_mut_cnt[index]++;
	}
}
static inline void record_mutation(int index)
{//record effective mutation when new coverage is found we look back and make statistics
	if(index >=0 && index < MUT_NUM){
		one_fuzz_mut_cnt[index]++;
	}
}
#define RANDOM_BOUND 90 //85%
#define VALUE_CHANGE_STRATEGY_BOUND  75//75%

static inline int binary_search(const int values[],int len,int query_value){

	int sum=values[len-1];
	if(query_value>sum || query_value<0){abort();
		FATAL("binary_search ERROR query_value=%d,sum=%d",query_value,sum);
	}
	//Binrary search for the interval [valid_mut[x][1],valid_mut[x+1][1]] at which query located
	//[0,valid_mut[0][1],valid_mut[1][1],...]
	//   ^               ^
	//   |               1 = x+1
	//   0 = x
	//We select mutation code from the index of right boundary 'x+1'.
	int low=0,center,high=len-1;
	while(low<high) {
		center=(low+high)/2;
		if(query_value<values[center]) {
			high=center-1;
		} else {
			low=center+1;
		}
	}
	return low;
	//low is the index we want.
}

static inline int gen_pos_from_record(Record *r,int debug)
{
	int sum=0;
	map_iter_t iter = map_iter(&r->P);
	const char *key;
	int positions[1<<12];
	int p_cnt=0;
	while ((key = map_next(&r->P, &iter))) {
		int cnt=(int)(size_t)(*map_get(&r->P, key));
		if(debug)OKF("%s -> %d", key, cnt);
		sum+=cnt;
		positions[p_cnt++]=atoi(key);
	}
	if(p_cnt==0||sum==0){
		//There exists break statements in case:{2,3,6-9,11,12-16} of havoc_stage, as we do not have inputs longer enough.
		//so tmp record is empty, the variable changing is caused by slices.
		return -1;//TODO: handle this case;
	}
	return positions[UR(p_cnt)];
	int rand=UR(sum);
	sum=0;
	iter = map_iter(&r->P);
	while ((key = map_next(&r->P, &iter))) {
		int cnt=(int)(size_t)(*map_get(&r->P, key));
		sum+=cnt;
		if(sum>=rand){
			//OKF("=>%s -> %d", key, cnt);
			break;
		}
	}
	return atoi(key);
}
static inline int gen_pos_from_record_list(Record * record_list, int debug)
{
	if(!record_list){
		FATAL("record_list==NULL !");
		return -1;
	}
	int sum=0;
	const char *key;
	int positions[1<<12];
	int p_cnt=0;
	for(Record *r=record_list;r!=NULL;r=r->next){
		map_iter_t iter = map_iter(&r->P);
		while ((key = map_next(&r->P, &iter))) {
			int cnt=(int)(size_t)(*map_get(&r->P, key));
			if(debug)OKF("%s -> %d", key, cnt);
			sum+=cnt;
			positions[p_cnt++]=atoi(key);
		}
	}
	return positions[UR(p_cnt)];
	int rand=UR(sum);
	sum=0;
	for(Record *r=record_list;r!=NULL;r=r->next){
		map_iter_t iter = map_iter(&r->P);
		while ((key = map_next(&r->P, &iter))) {
			int cnt=(int)(size_t)(*map_get(&r->P, key));
			sum+=cnt;
			if(sum>=rand){
				//OKF("=>%s -> %d", key, cnt);
				return atoi(key);
			}
		}
	}
	FATAL("record_list!=NULL, but no recorded positions!");
	return -1;//this should not happen

}
static inline Record * select_record(Record *record_list)
{
	if(!record_list) return NULL;
	double sum=0;
	Record *r=NULL;
	for(r =record_list;r!=NULL;r=r->next)
	{
		//sum+=(max_gd-r->distance+1);
		if(r->distance-0.0<0.0001)
		{
			FATAL("Illegal Zero Distance! r->distance=%f,min_gd=%f",r->distance,min_gd);
		}
		sum+=200/(r->distance-0.95)+1;
		//OKF("r=%p,distance=%f,sum=%f",r,r->distance,sum);
	}
	if(sum==0)FATAL("ERROR when calculating sum r=%p",r);
	int rand0=UR((int)(sum));
	sum=0;
	for(r =record_list;r!=NULL;r=r->next)
	{
		//sum2+=(max_gd-r->distance+1);
		sum+=200/(r->distance-0.95)+1;
		//OKF("sum:%f,rand0=%d",sum,rand0);
		if(sum-rand0>=0.0001){
			break;//we select a record "r"
		}
	}
	return r;
}

static inline int init_answer_list(char * answer_str){
	char * answer=strdup(answer_str);
	OKF("#%s",answer);
	if(strstr(answer,":")){
		OKF("SWITCH");
		char* item=strtok(answer,",");
		do{
			if(!strstr(item,"-1")){
				(*strstr(item,":"))='\0';
				insert_value(&target_bb->answer_list,(u64)atoi(item));
			}
			item=strtok(NULL,",");
		}while(item);
		if(target_bb->answer_list.len>0){//insert a random value to trigger default; we cannot make sure it will success
			insert_value(&target_bb->answer_list,(u64)(UR(256)));
		}
	}else{
		//eq,ne
		//ugt,uge,ult,ule
		//sgt,sge,slt,sle
		u64 it=(u64)atoi(answer);
		u64 less=it-1;
		u64 more=it+1;
		insert_value(&target_bb->answer_list,less);
		insert_value(&target_bb->answer_list,more);
		insert_value(&target_bb->answer_list,it);
	}
	OKF("target_bb->answer_list.len=%d",target_bb->answer_list.len);
	return target_bb->answer_list.len;
}
static inline u8 unique_judge_value(u8 byte){
	int cnt=target_bb->c_focus->pos_focus->fuzz_cnt-1;//already increased
	OKF("fuzz_cnt:%d",cnt+1);
	if(cnt<0)FATAL("cnt:%d<0",cnt);
	int repeat;
	do{
		repeat=0;
		for(int i=0;i<cnt;i++){
			if(byte==target_bb->c_focus->pos_focus->fmap[i].input){
				repeat=1;
				byte=UR(256);
				break;
			}
		}
	}while(repeat);
	target_bb->c_focus->pos_focus->fmap[cnt].input=byte;//set FMAP of pos_focus during JUDGE stage
	return byte;
}
static inline int dispatch_random(u32 range,s32 len,u32 * arg)
{//still buggy
	arg[0]=-1;
	arg[1]=-1;

	if (mut_prior_mode||target_bb->c_focus)
	{

		/* find suitable template strategy */
		Strategy *s = get_strategy(queue_cur->exec_path_len);
		//check if there exists an margin BB with distance==min_d(minimal distance of current margin BB set)
		//and we do not have corresponding variable impacting records.
		//if so we linearly search for good position
		//if search failed we go to random
//		int with_dict[]={10,15,1,4,5};//they are cases without break exception
//		int without_dict[]={10,1,4,5};//they are cases without break exception

		if(!target_bb->node||target_bb->node->branch_type==STATE_BASED){
			goto monitor;
		}
		// note that we must handle the case when queue_cur->exec_path_len==0 before here
		// to make queue_cur->exec_path_len>0 always satisfied.
		if(queue_cur->exec_path_len<=0){
			FATAL("queue_cur->exec_path_len:%d<=0",queue_cur->exec_path_len);
		}
		//note that target_bb->c_focus==NULL and arget_bb->c_list!=NULL may happen
		//when a child seed launch an linear scanning durring the fuzzing stage of the father
		//TIP:target_bb->c_focus is set in the loop of main().
		if(target_bb->c_focus){
			if(target_bb->solving_stage==SCAN){// || target_bb->scanning_tasks>0 && target_bb->c_focus->fuzz_pos>=0){
				//linear search to attack this branch
				if(0<=target_bb->c_focus->fuzz_pos && target_bb->c_focus->fuzz_pos <len){
					arg[0]=10;
					arg[1]=target_bb->c_focus->fuzz_pos++;
					return 1;
				}else if(target_bb->c_focus->fuzz_pos >= len){
					arg[1]=target_bb->c_focus->fuzz_pos=-1;
					target_bb->scanning_tasks=0;
					LinkedPosition *p=target_bb->c_focus->eff_pos_list.head;
					while(p){
						OKF("@%d",p->pos);
						p=p->next;
					}
					OKF("finish linear search! len=%d, changed=%d",len,target_bb->c_focus->eff_pos_list.len);
					if(target_bb->c_focus->eff_pos_list.len==0){//cannot judge it as field value based branch
						target_bb->node->branch_type=STATE_BASED;
						target_bb->solving_stage=RANDOM;
						remove_candidates();
						remove_values(&target_bb->value_list);
						remove_values(&target_bb->answer_list);
						FATAL("target rid=%d,%s is a state based target",target_bb->node->rid,target_bb->node->bbname);
						goto monitor;
					}else{//target_bb->c_focus->eff_pos_list.len>0
						target_bb->solving_stage=JUDGE;//switch to JUDGE stage
						target_bb->c_focus->pos_focus=target_bb->c_focus->eff_pos_list.head;
					}
				}
			}
			if(target_bb->solving_stage==JUDGE){
				if(target_bb->c_focus->pos_focus->fuzz_cnt<FMAP_LEN){
					target_bb->c_focus->pos_focus->fuzz_cnt++;
				}else{
					display_fmap(target_bb->c_focus->pos_focus);//lets check the result
					LinkedPosition *p=target_bb->c_focus->pos_focus;
					target_bb->c_focus->pos_focus=target_bb->c_focus->pos_focus->next;
					if(!p->is_field){
						OKF("before delete eff_pos_list.len=%d",target_bb->c_focus->eff_pos_list.len);
						delete_position(&target_bb->c_focus->eff_pos_list,p);
						OKF("after delete eff_pos_list.len=%d",target_bb->c_focus->eff_pos_list.len);
					}

					if(target_bb->c_focus->pos_focus){
						target_bb->c_focus->pos_focus->fuzz_cnt++;
					}else{
						OKF("Finish type detection!");
						OKF("target_bb: %s,rid=%d",target_bb->node->bbname,target_bb->node->rid);
						target_bb->solving_stage=RANDOM;
						if(target_bb->node->branch_type==UNKNOWN){
							target_bb->node->branch_type=STATE_BASED;
							FATAL("target_bb:%s is state based target",target_bb->node->bbname);
						}else if(target_bb->node->branch_type==FIELD_BASED){
							//if(target_bb->c_focus->eff_pos_list.head->answer)
							if(target_bb->node->answer_str){
								target_bb->solving_stage=ANSWER;
								OKF("ANSWER_STR:%s",target_bb->node->answer_str);
								if(init_answer_list(target_bb->node->answer_str)>0){
									display_value_list(&target_bb->answer_list);
									target_bb->answer_focus=target_bb->answer_list.head;
									OKF("v=%llx",target_bb->answer_focus->v);
									arg[0]=-1;//signal that we have answer, fetch it from target_bb->answer_focus;
									return 1;
								}
							}
						}
						goto monitor;
					}
				}
				if(!target_bb->c_focus->pos_focus)
					FATAL("This should not happen!");
				arg[0]=10;
				arg[1]=target_bb->c_focus->pos_focus->pos;
				OKF("Set pos:0x%x",arg[1]);
				return 1;
			}else if(target_bb->solving_stage==ANSWER){
				target_bb->answer_focus=target_bb->answer_focus->next;
				if(target_bb->answer_focus){
					arg[0]=-1;//signal that we have answer, fetch it from target_bb->answer_focus;
					return 1;
				}else{
					target_bb->solving_stage=RANDOM;
				}
			}
		}
monitor:
		if(s->record_list)
		{
			int valid_mut[MUT_NUM];
			int bound_values[MUT_NUM];
			int valid_mut_cnt=0;
			int sum3=0;

			int perfect_mut[MUT_NUM];
			int perfect_mut_cnt=0;
//			float avg=0;
//			int cnnt;
//			for(int i=1;i<MUT_NUM;i++)
//			{
//				if(mut_score[i]>1)
//				{
//					avg+=mut_score[i];
//					cnnt++;
//				}
//			}
//			avg/=cnnt;

			Record *r=select_record(s->record_list);

			for(int i=1;i<MUT_NUM;i++)
			{
				if(mut_score[i]>=r->M[i]&&mut_score[i]>1)//define the validity of mutator
				//if(mut_score[i]>=mut_cnt[i]&&mut_score[i]>1)//&&mut_score[i]>avg)
				{
					perfect_mut[perfect_mut_cnt]=i;
					//OKF("##%02d,%02d|%02d|%s",i,mut_score[i],mut_cnt[i],get_description(i));
					perfect_mut_cnt++;
				}
				if(mut_score[i]>0){//need improve to link list
					valid_mut[valid_mut_cnt]=i;//mut code
					sum3+=mut_score[i];
					bound_values[valid_mut_cnt]=sum3;//bounds which refer to index possibility in x axis
					valid_mut_cnt++;
				}
			}
			int rand=UR(100);

			if (mut_prior_mode==1 && valid_mut_cnt>0 && rand<VALUE_CHANGE_STRATEGY_BOUND){//75%
				//select mutation
				int th=35;//35//40;
				if(target_bb->node->branch_type==STATE_BASED){
					th=40;//40//75
				}
				if(perfect_mut_cnt>0 && rand <th){
					arg[0]=perfect_mut[UR(perfect_mut_cnt)];
				}else if(valid_mut_cnt>0 && rand < 70){//70
					int index=binary_search(bound_values,valid_mut_cnt,UR(sum3));
					arg[0]=valid_mut[index];
					//arg[0]=valid_mut[UR(valid_mut_cnt)];
				}else{
					arg[0]=UR(range);
				}
				if(target_bb->node->branch_type==STATE_BASED && rand%2>0){
					arg[1]=-1;
				}else{
					arg[1]=gen_pos_from_record(r,0);
				}
				//select position

//				if(target_bb->node->branch_type==2){//share position
//					arg[1]=gen_pos_from_record_list(0);
//				}else{
//					arg[1]=gen_pos_from_record(r,0);
//				}
			}
		}
	}
	if(arg[0]==-1){
random:
		arg[0]=UR(range);
		//arg[1]=-1;
		random_mut++;
	}else{
		monitor_mut++;
	}
	return 0;
}


//static int all_pos_touched=0;
//static int all_full=0;

static inline int UR_FIX(int range)
{
	return UR(range);/*
	if(all_pos_touched && all_full){
		return UR(range);
	}
	int pos=0;
	int iter=0;
	for(int find_virgin=0;!find_virgin;iter++)
	{
		int miss=0;
		for(int i=0;i<margin_bb_count;i++)
		{
			int index=rid2index[margin_bb_rid[i]];
			if(vertex_index[index].invalid_positions)
			{
				char * pos_str=alloc_printf("%d",pos);
				int *cnt=map_get(vertex_index[index].invalid_positions, pos_str);
				ck_free(pos_str);
				if(!cnt){
					return pos;
				}else if(all_pos_touched){
					return UR(range);
					if(all_full){
						return UR(range);
					}else if(*cnt<256){
						return pos;
					}else{
						pos+=1;
						if(pos>=range)
						{
							all_full=1;
							return UR(range);
						}
						break;
					}
				}else{
					pos+=1;
					if(pos>=range)
					{
						all_pos_touched=1;
						pos=0;
						break;
					}
					break;
				}
			}else{
				miss++;
			}
		}
		if(miss==margin_bb_count){
			return UR(range);
		}
		OKF("iter:%d",iter);
	}FATAL("DEADCODE! touched");*/
}
/* add by yangke end */

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

static u8 fuzz_one(char** argv) {

  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

  }

  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!dumb_mode && (stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  /* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum) {
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);

  } else {

    blocks_eff_select += eff_cnt;

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith) goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  /* Insertion of user-supplied extras. */

  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt) goto skip_extras;

  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */
  /* add by yangke start */

  s32 my_stage_max=stage_max;

  if(mutation_score_initialized==0){
	  init_mutation_score();
  	  mutation_score_initialized=1;
  }

  cleanup_mutation_record();
  if (cycles_wo_finds >=threshold_cycles_wo_finds){//in this case we take small steps
	  /*if(!mut_prior_mode&&t1==0){
		  t1=cycles_wo_finds;
		  t3=cycles_wo_finds+stride;
	  }*/
	  my_stage_max=stage_max<max_mut_loop_bound?stage_max:max_mut_loop_bound;
	  //OKF("stage_max=%d,max_mut_loop_bound=%d",stage_max,max_mut_loop_bound);
	  //flush out rubbish and next time we record new candidates
	  if (value_changing_mutation_record_initialized==0){
	  	  init_value_changing_mutation_record();
	  	  value_changing_mutation_record_initialized=1;
	  }
	  cleanup_possible_value_changing_mutation_record();
  }/*else{
	  mut_prior_mode=0;
	  //my_stage_max=stage_max;
	  cleanup_value_changing_mutation_record();
  }*/

  /* add by yangke end */
  for (stage_cur = 0; stage_cur < my_stage_max; stage_cur++) {

	//UR is a inline random number generation function, see afl-fuzz.c:406
    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    /* add by yangke start */
    u32 my_use_stacking=use_stacking;
    if(cycles_wo_finds >=threshold_cycles_wo_finds){//in this case we take small steps
    	my_use_stacking=use_stacking<max_mut_loop_bound?use_stacking:max_mut_loop_bound;
    	//OKF("use_stacking=%d,max_mut_loop_bound=%d",use_stacking,max_mut_loop_bound);
    }
    /* add by yangke end */

    for (i = 0; i < my_use_stacking; i++) {

      /* add by yangke start */
      u32 arg[3];//to store opcode and pos
      //if(mut_prior_mode){
      if(cycles_wo_finds >=threshold_cycles_wo_finds){
    	 if(queue_cur->exec_path_len==0){
			 arg[0]=-1;//do nothing
			 linear_search=1;
    	 }else{
    	     linear_search=dispatch_random(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0),temp_len,arg);
    	     if(arg[0]==-1){

    	    	 if(target_bb->solving_stage!=ANSWER||target_bb->node->branch_type!=FIELD_BASED){
    	    		 FATAL("This should not happen!!");
    	    	 }
    	    	 OKF("ANSWER:mem[0x%x]=0x%x",target_bb->c_focus->eff_pos_list.head->pos,(u8)target_bb->answer_focus->v);

    	    	 out_buf[target_bb->c_focus->eff_pos_list.head->pos]=(u8)target_bb->answer_focus->v;
    	    	 //out_buf[target_bb->c_focus->eff_pos_list.head->pos]=*(target_bb->c_focus->eff_pos_list.head->answer);
    	     }
    	 }
    	 if(linear_search){//||target_bb->scanning_tasks||target_bb->solving_stage==JUDGE
    		 stage_cur=my_stage_max;
    		 i=my_use_stacking;
    	 }
    	 record_mutation(arg[0]);
      }else{
    	 arg[0]=UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0));//original AFLGO setting
    	 arg[1]=-1;// be careful when it is used as the initial value is invalid pos -1
      }
      //arg[0]=10;
      /*int arr[3]={8,9,11};
      arg[0]=arr[UR(3)];
      arg[1]=15;// cheat for libturbojpeg jdmarker:659 google-fuzzer-testsuite 12s
      */
      /* add by yangke end */
      switch (arg[0]) {

      case 0:

          /* Flip a single bit somewhere. Spooky! */
    	  /* add by yangke start */
    	  if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len<<3)){
    		  arg[1]=UR_FIX(temp_len << 3);
    	  }//else{arg[1]= (arg[1]>>3)+UR(8));}
    	  if (cycles_wo_finds >=threshold_cycles_wo_finds){
    		  record_possible_value_changing_mutation(0,arg[1]>>3);
    	  }

    	  FLIP_BIT(out_buf,arg[1]);//be careful of heap overflow


          /* add by yangke end */

          break;

        case 1: 

          /* Set byte to interesting value. */

          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=temp_len){
        	  arg[1]=UR_FIX(temp_len);
		  }
          if (cycles_wo_finds >=threshold_cycles_wo_finds){
        	  record_possible_value_changing_mutation(1,arg[1]);
          }

          out_buf[arg[1]] = interesting_8[UR(sizeof(interesting_8))];

          /* add by yangke end */

          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          /* add by yangke start */

          if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-1)){
        	  arg[1]=UR_FIX(temp_len - 1);
          }
          if (cycles_wo_finds >=threshold_cycles_wo_finds){
        	  record_possible_value_changing_mutation(2,arg[1]);
          }

          if (UR(2)) {

            *(u16*)(out_buf + arg[1]) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + arg[1]) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }
          /* add by yangke end */



          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-3)){
              arg[1]=UR_FIX(temp_len - 3);
          }
          if (cycles_wo_finds >=threshold_cycles_wo_finds){
        	  record_possible_value_changing_mutation(3,arg[1]);
          }

          if (UR(2)) {
  
            *(u32*)(out_buf + arg[1]) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + arg[1]) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }
          /* add by yangke end */

          break;

        case 4:

          /* Randomly subtract from byte. */

          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=temp_len){
			  arg[1]=UR_FIX(temp_len);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(4,arg[1]);
		  }

          out_buf[arg[1]] -= 1 + UR(ARITH_MAX);
          /* add by yangke end */
          break;

        case 5:

          /* Randomly add to byte. */

          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=temp_len){
			  arg[1]=UR_FIX(temp_len);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(5,arg[1]);
		  }

          out_buf[arg[1]] += 1 + UR(ARITH_MAX);
          /* add by yangke end */
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;
          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-1)){
			  arg[1]=UR_FIX(temp_len-1);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(6,arg[1]);
		  }

          if (UR(2)) {

            u32 pos = arg[1];

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = arg[1];
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }
          /* add by yangke end */

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          /* add by yangke start */
          if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-1)){
			  arg[1]=UR_FIX(temp_len-1);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(7,arg[1]);
		  }
          if (UR(2)) {

            u32 pos = arg[1];

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = arg[1];
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }
          /* add by yangke end */

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          /* add by yangke start */
		  if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-3)){
			  arg[1]=UR_FIX(temp_len - 3);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(8,arg[1]);
		  }

          if (UR(2)) {

            u32 pos = arg[1];

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = arg[1];
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }
          /* add by yangke end */

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          /* add by yangke start */
		  if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len-3)){
			  arg[1]=UR_FIX(temp_len - 3);
		  }
		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(9,arg[1]);
		  }
          if (UR(2)) {

            u32 pos = arg[1];

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = arg[1];
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }
          /* add by yangke end */

          break;

        case 10:{

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          /* add by yangke start */
          //out_buf[0x1d0]=0xff;out_buf[0x1d1]=0xff;out_buf[0x2cb]=0x1;


          if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len)){
			  arg[1]=UR_FIX(temp_len);
		  }
		  //if(arg[1]==0x1d1)FATAL("Find it");
          //if(linear_search)arg[1]=0x1d1;

		  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  record_possible_value_changing_mutation(10,arg[1]);
		  }

		  out_buf[arg[1]] ^= 1 + UR(255);
		  if(target_bb->solving_stage==JUDGE){
			  out_buf[arg[1]]=unique_judge_value(out_buf[arg[1]]);
			  OKF("JUDGE:mem[0x%x]=0x%x",arg[1],out_buf[arg[1]]);
		  }else if(target_bb->scanning_tasks>0 || target_bb->solving_stage==SCAN){
			  OKF("SCAN:mem[0x%x]=0x%x",arg[1],out_buf[arg[1]]);
		  }

//          if(linear_search){
//          	  out_buf[0x1d0]=0xff;out_buf[0x1d1]=0xff;out_buf[0x2cb]=0x1;
//			  for(int i=0x1d0;i<0x2cb+16;i+=16){
//				  OKF("%x %x %x %x %x %x %x %x",out_buf[i],out_buf[i+1],out_buf[i+2],out_buf[i+3],
//						  out_buf[i+4],out_buf[i+5],out_buf[i+6],out_buf[i+7]);
//			  }
//          }
//          else{
//        	  out_buf[arg[1]] ^= 1 + UR(255);
//          }
          /* add by yangke end */
          break;
        }
        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);

            /* add by yangke start */
            if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len - del_len + 1)){
            	arg[1]=UR_FIX(temp_len - del_len + 1);
			}
			if (cycles_wo_finds >=threshold_cycles_wo_finds){
				record_possible_value_changing_mutation(arg[0],arg[1]);
			}

            del_from = arg[1];
            /* add by yangke end */

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {

              clone_len  = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);

            } else {

              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            /* add by yangke start */
            if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len)){
                arg[1]=UR_FIX(temp_len);
            }
            if (cycles_wo_finds >=threshold_cycles_wo_finds){
                record_possible_value_changing_mutation(13,arg[1]);
            }
            clone_to   = arg[1];
            /* add by yangke end */

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

          }

          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            /* add by yangke start */

			if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len - copy_len + 1)){
				arg[1]=UR_FIX(temp_len - copy_len + 1);
			}
			if (cycles_wo_finds >=threshold_cycles_wo_finds){
				record_possible_value_changing_mutation(14,arg[1]);
			}
            copy_to   = arg[1];
            /* add by yangke end */

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */

        case 15: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;
              /* add by yangke start */
			  if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len - extra_len + 1)){
				  arg[1]=UR_FIX(temp_len - extra_len + 1);
			  }
			  if (cycles_wo_finds >=threshold_cycles_wo_finds){
			  	  record_possible_value_changing_mutation(15,arg[1]);
			  }
              insert_at = arg[1];
              /* add by yangke end */
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              /* add by yangke start */
			  if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len - extra_len + 1)){
				  arg[1]=UR_FIX(temp_len - extra_len + 1);
			  }
			  if (cycles_wo_finds >=threshold_cycles_wo_finds){
				  record_possible_value_changing_mutation(15,arg[1]);
			  }
			  insert_at = arg[1];
              /* add by yangke end */
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

            }

            break;

          }

        case 16: {
            /* add by yangke start */
		    if (!mut_prior_mode||arg[1]==-1||arg[1]>=(temp_len + 1)){
			    arg[1]=UR_FIX(temp_len + 1);
		    }
		    if (cycles_wo_finds >=threshold_cycles_wo_finds){
			    record_possible_value_changing_mutation(16,arg[1]);
		    }
		    u32 use_extra, extra_len, insert_at = arg[1];
		    /* add by yangke end */

            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }
      total_mut_cnt++;
    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (!linear_search&&use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);
    /* add by yangke start*/
    /*if (cycles_wo_finds >=threshold_cycles_wo_finds){
    	//splice_cycle+=4;
    	splice_cycle+=stage_max/max_mut_loop_bound<SPLICE_CYCLES/2?stage_max/max_mut_loop_bound:SPLICE_CYCLES/2;
    }*/
    /* add by yangke end*/
    goto havoc_stage;//original AFLGO

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

#undef FLIP_BIT

}


/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char** argv) {

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */    

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur  = 0;
    stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 || 
          syncing_case < min_accept) continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept)
        next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) {
         ck_free(path);
         continue;
      }

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        fault = run_target(argv, exec_tmout);

        if (stop_soon) return;

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);
        syncing_party = 0;

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq)) show_stats();

      }

      ck_free(path);
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
    
  }  

  closedir(sd);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}


/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  skip_requested = 1;

}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1; 
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1; 
    kill(forksrv_pid, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

EXP_ST void check_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

  if (getenv("AFL_SKIP_BIN_CHECK")) return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);

  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");

  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");

  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) uses_asan = 1;

  /* Detect persistent & deferred init signatures in the binary. */

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;

  } else if (getenv("AFL_PERSISTENT")) {

    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");

  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);

  } else if (getenv("AFL_DEFER_FORKSRV")) {

    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");

  }

  if (munmap(f_data, f_len)) PFATAL("unmap() failed");

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {

    if (sync_id) {

      use_banner = sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) use_banner = name; else use_banner = trim + 1;

    }

  }

  if (strlen(use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}


/* Check if we're on TTY. */

static void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

}


/* Check terminal dimensions after resize. */

static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = 1;

}



/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Directed fuzzing specific settings:\n\n"

       "  -z schedule   - temperature-based power schedules\n"
       "                  {exp, log, lin, quad} (Default: exp)\n"
       "  -c min        - time from start when SA enters exploitation\n"
       "                  in secs (s), mins (m), hrs (h), or days (d)\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"     
 
       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Prepare output directories and fds. */

EXP_ST void setup_dirs_fds(void) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
      PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  } else {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id) {

    tmp = alloc_printf("%s/.synced/", out_dir);
    if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */

}


/* Setup the output file for fuzzed data, if not using -f. */

EXP_ST void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void) {

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of 
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */
  
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as timeouts, please run the\n" 
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
      FATAL("Pipe at the beginning of 'core_pattern'");

  }
 
  close(fd);

#endif /* ^__APPLE__ */

}


/* Check CPU governor. */

static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if (cur_runnable + 1 <= cpu_core_count) {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
  
      }

    }

  } else {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}


/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void) {

  u8* x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");

  }

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }

  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir  = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  clear_screen = 1;
}


/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

  }

  x = getenv("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code="
            STRINGIFY(MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

  }

} 


/* Detect @@ in args. */

EXP_ST void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

EXP_ST void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}


/* Rewrite argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}


/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char** argv) {

  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;
  
  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}

#ifndef AFL_LIB

int stricmp(char const *a, char const *b) {
  int d;
  for (;; a++, b++) {
    d = tolower(*a) - tolower(*b);
    if (d != 0 || !*a)
      return d;
  }
}

/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "aflgo (yeah!) " cBRI VERSION cRST "\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:Qz:c:E:")) > 0)

    switch (opt) {

      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */

          u8* c;

          if (sync_id) FATAL("Multiple -S or -M options not supported");
          sync_id = ck_strdup(optarg);

          if ((c = strchr(sync_id, ':'))) {

            *c = 0;

            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                !master_id || !master_max || master_id > master_max ||
                master_max > 1000000) FATAL("Bogus master ID passed to -M");

          }

          force_deterministic = 1;

        }

        break;

      case 'S': 

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 'x': /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': { /* timeout */

          u8 suffix = 0;

          if (timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }

      case 'm': { /* mem limit */

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 'd': /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B': /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C': /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;

        break;

      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'z': /* Cooling schedule for Directed Fuzzing */

        if (!stricmp(optarg, "exp"))
          cooling_schedule = SAN_EXP;
        else if (!stricmp(optarg, "log"))
          cooling_schedule = SAN_LOG;
        else if (!stricmp(optarg, "lin"))
          cooling_schedule = SAN_LIN;
        else if (!stricmp(optarg, "quad"))
          cooling_schedule = SAN_QUAD;
        else
          PFATAL ("Unknown value for option -z");

        break;

      case 'c': { /* cut-off time for cooling schedule */

          u8 suffix = 'm';

          if (sscanf(optarg, "%u%c", &t_x, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -c");

          switch (suffix) {

            case 's': t_x /= 60; break;
            case 'm': break;
            case 'h': t_x *= 60; break;
            case 'd': t_x *= 60 * 24; break;

            default:  FATAL("Unsupported suffix or bad syntax for -c");

          }

        }
        break;
      /* add by yangke start */
      case 'E': /* Input Directory for Static Control Flow Graph info */
    	if(!strcmp(optarg, "")) FATAL("Please specify the directory for CFG. e.g -E <temp_dir>");
    	temp_dir=optarg;
        break;
      /* add by yangke end */
      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  OKF("Running with " cBRI "%s" cRST " schedule and time-to-exploitation set to " cBRI "%d minutes" cRST,
      cooling_schedule == SAN_EXP ? "EXP" :
      cooling_schedule == SAN_LOG ? "LOG" :
      cooling_schedule == SAN_LIN ? "LIN" :
      cooling_schedule == SAN_QUAD ? "QUAD" : "???",
      t_x
  );

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode) {

    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }

  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))      no_arith = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  setup_dirs_fds();
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  /* add by yangke start */
  if(!target_bb){
  	  target_bb=(Target *)malloc(sizeof(Target));
  	  target_bb->node=NULL;
  	  target_bb->born_cycle=-1;
  	  target_bb->max_len=0;
  	  strcpy(target_bb->function,"");
  	  target_bb->scanning_tasks=0;
  	  target_bb->solving_stage=RANDOM;
  	  target_bb->c_focus=NULL;
  	  target_bb->c_list=NULL;
  	  target_bb->c_list_len=0;
  	  target_bb->value_list.head=NULL;
  	  target_bb->value_list.len=0;
  	  target_bb->answer_list.head=NULL;
  	  target_bb->answer_list.len=0;
  	  target_bb->answer_focus=NULL;
  }

  while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

	 /* add by yangke end */
      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) {
        	cycles_wo_finds++;
        }else{
        	use_splicing = 1;
        }

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);

    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(use_argv);

    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;
    if(target_bb->node && target_bb->c_list && target_bb->node->branch_type!=STATE_BASED){
  	  if(target_bb->c_list_len>1)FATAL("This should not happen!!");
      if(!target_bb->c_focus){
  		target_bb->c_focus=target_bb->c_list;
  	  }else {
  		target_bb->c_focus=target_bb->c_focus->next;
  		if(!target_bb->c_focus){
  			target_bb->c_focus=target_bb->c_list;
  		}
  	  }//do not move c_focus when target_bb->node->branch_type==1
  	  queue_cur=target_bb->c_focus->entry;
    }else{
    	queue_cur = queue_cur->next;
    }
    current_entry++;
  }

  if (queue_cur) show_stats();

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.)\n", doc_path);

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  destroy_all_cfg();
  destroy_target();
  destroy_records();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif /* !AFL_LIB */
