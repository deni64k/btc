#pragma once

#if defined(_WIN32)
#define CLOCK_REALTIME 0
namespace {
    int clock_gettime(int, struct timespec* spec)      //C-file part
    {
        __int64 wintime; GetSystemTimeAsFileTime((FILETIME*)&wintime);
        wintime -= 116444736000000000i64;  //1jan1601 to 1jan1970
        spec->tv_sec = wintime / 10000000i64;            // seconds
        spec->tv_nsec = wintime % 10000000i64 * 100;      // nano-seconds
        return 0;
    }
}
#endif

namespace common {

struct profile {
  void start() {
    clock_gettime(CLOCK_REALTIME, &start_);
  }

  void finish() {
    clock_gettime(CLOCK_REALTIME, &finish_);
  }

  double seconds() {
    auto sec  = finish_.tv_sec  - start_.tv_sec;
    auto nsec = finish_.tv_nsec - start_.tv_nsec;
    if (start_.tv_nsec > finish_.tv_nsec) {
      --sec;
      nsec += 1000000000ULL;
    }
    return static_cast<double>(sec) + static_cast<double>(nsec) / 1e9;
  }

 private:
  timespec start_;
  timespec finish_;  
};

}
