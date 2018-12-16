#pragma once

namespace common {

struct profile {
  void start() {
    clock_gettime(CLOCK_REALTIME, &start_);
  }

  void finish() {
    clock_gettime(CLOCK_REALTIME, &finish_);
  }

  double seconds() {
    long sec  = finish_.tv_sec  - start_.tv_sec;
    long nsec = finish_.tv_nsec - start_.tv_nsec;
    if (start_.tv_nsec > finish_.tv_nsec) {
      --sec;
      nsec += 1000000000ULL;
    }
    return double(sec) + double(nsec) / 1e9;
  }

 private:
  timespec start_;
  timespec finish_;  
};

}
