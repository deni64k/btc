#pragma once

#include "common/types.hxx"
#include "opencl/opencl.hxx"

struct sha256_program {
  static constexpr std::size_t const max_batch_size = 128*1024;
  static constexpr std::size_t const nonce_step = 1024;
  sha256_program(opencl::context& ctx/*,
                 hash32_t target_hash*/)
      : ctx_{ctx} {
    cl_int rv;

    std::vector<char> hasher_prog_source;
    std::ifstream hasher_prog_is("shaders/hasher.cl");
    while (true) {
      char buf[512];
      auto rv = hasher_prog_is.readsome(buf, sizeof(buf));
      if (!rv)
        break;
      std::copy(buf, buf + rv, std::back_inserter(hasher_prog_source));
    }
    program_ = ctx_.make_program(hasher_prog_source.data(), hasher_prog_source.size());
    hasher_ = clCreateKernel(program_.program(), "mine", &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateKernel failed");

    mem_target_hash_ = clCreateBuffer(
        ctx_.ctx(),
        // CL_MEM_READ_ONLY | CL_MEM_HOST_NO_ACCESS | CL_MEM_COPY_HOST_PTR,
        CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY,
        // target_hash.size() * sizeof(target_hash[0]), target_hash.data(), &rv);
        sizeof(hash32_t), nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_message_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY,
        256, nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_message_len_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY,
        sizeof(cl_uint), nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_nonce_begins_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY,
        sizeof(std::uint32_t) * max_batch_size, nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_nonce_ends_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY,
        sizeof(std::uint32_t) * max_batch_size, nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_min_hashes_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_WRITE | CL_MEM_HOST_READ_ONLY,
        sizeof(hash32_t) * max_batch_size, nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_min_nonces_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_READ_WRITE | CL_MEM_HOST_READ_ONLY,
        sizeof(std::uint32_t) * max_batch_size, nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    rv = clSetKernelArg(hasher_, 0, sizeof(mem_target_hash_), &mem_target_hash_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 1, sizeof(mem_message_), &mem_message_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 2, sizeof(mem_message_len_), &mem_message_len_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 3, sizeof(mem_nonce_begins_), &mem_nonce_begins_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 4, sizeof(mem_nonce_ends_), &mem_nonce_ends_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 5, sizeof(mem_min_hashes_), &mem_min_hashes_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 6, sizeof(mem_min_nonces_), &mem_min_nonces_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
  }

  ~sha256_program() {
    cl_int rv;
    rv = clReleaseMemObject(mem_target_hash_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_message_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_message_len_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_nonce_begins_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_nonce_ends_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_min_hashes_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseMemObject(mem_min_nonces_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseMemObject failed";
      return;
    }
    rv = clReleaseKernel(hasher_);
    if (rv != CL_SUCCESS) {
      ERROR() << "clReleaseKernel failed";
      return;
    }
  }

  std::pair<hash32_t, std::uint32_t>
  operator () (hash32_t target_hash,
               std::vector<std::uint8_t> const& message,
               std::uint32_t nonce_begin,
               std::uint32_t nonce_end) {
    std::size_t const nonce_iterations = (nonce_end - nonce_begin + nonce_step - 1) / nonce_step;
    std::vector<std::uint32_t> nonce_begins;
    std::vector<std::uint32_t> nonce_ends;
    nonce_begins.reserve(nonce_iterations);
    nonce_ends.reserve(nonce_iterations);
    
    std::uint32_t min_nonce;
    hash32_t min_hash;
    std::fill(min_hash.begin(), min_hash.end(), 0xffffffff);

    unsigned i = 0;
    for (; i < nonce_iterations - 1; ++i) {
      nonce_begins.push_back(nonce_begin + nonce_step * i);
      nonce_ends.push_back(nonce_begin + nonce_step * i + (nonce_step-1));
    }
    nonce_begins.push_back(nonce_begin + nonce_step * i);
    nonce_ends.push_back(nonce_end);

    cl_int  rv;
    cl_uint len = message.size();
    rv = clEnqueueWriteBuffer(ctx_.command_queue(), mem_target_hash_, CL_TRUE, 0,
                              target_hash.size() * sizeof(target_hash[0]), target_hash.data(),
                              0, nullptr, nullptr);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clEnqueueWriteBuffer failed");
    rv = clEnqueueWriteBuffer(ctx_.command_queue(), mem_message_, CL_TRUE, 0,
                              message.size(), message.data(), 0, nullptr, nullptr);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clEnqueueWriteBuffer failed");
    rv = clEnqueueWriteBuffer(ctx_.command_queue(), mem_message_len_, CL_TRUE, 0,
                              sizeof(len), &len, 0, nullptr, nullptr);

    struct timespec hashing_start, hashing_finish;
    clock_gettime(CLOCK_REALTIME, &hashing_start);

    for (unsigned offset = 0; offset < nonce_iterations; ) {
      struct timespec iteration_start, iteration_finish;
      clock_gettime(CLOCK_REALTIME, &iteration_start);

      unsigned rem = nonce_iterations - offset;
      unsigned batch_size = std::min<unsigned>(rem, max_batch_size);

      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueWriteBuffer failed");
      rv = clEnqueueWriteBuffer(ctx_.command_queue(), mem_nonce_begins_, CL_TRUE, 0,
                                batch_size * sizeof(nonce_begins[0]), &nonce_begins[offset],
                                0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueWriteBuffer failed");
      rv = clEnqueueWriteBuffer(ctx_.command_queue(), mem_nonce_ends_, CL_TRUE, 0,
                                batch_size * sizeof(nonce_ends[0]), &nonce_ends[offset],
                                0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueWriteBuffer failed");

      std::size_t global_item_size = batch_size;
      [[maybe_unused]] std::size_t local_item_size = 1;
      rv = clEnqueueNDRangeKernel(ctx_.command_queue(), hasher_, 1,
                                  nullptr, &global_item_size, nullptr,
                                  0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueNDRangeKernel failed");

      std::vector<hash32_t> min_hashes(batch_size);
      rv = clEnqueueReadBuffer(ctx_.command_queue(), mem_min_hashes_, CL_TRUE, 0, 
                               min_hashes.size() * sizeof(min_hashes[0]), min_hashes.data(),
                               0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueReadBuffer failed");

      std::vector<std::uint32_t> min_nonces(batch_size);
      rv = clEnqueueReadBuffer(ctx_.command_queue(), mem_min_nonces_, CL_TRUE, 0, 
                               min_nonces.size() * sizeof(min_nonces[0]), min_nonces.data(),
                               0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueReadBuffer failed");

      // std::for_each(min_hashes.begin(), min_hashes.end(),
      //               [](auto& x) { std::reverse(x.begin(), x.end()); });
      // for (auto& x : min_hashes) {
      //   INFO() << "min_hashes: " << std::hex << std::setfill('0')
      //          << std::setw(8) << x[0] << ' '
      //          << std::setw(8) << x[1] << ' '
      //          << std::setw(8) << x[2] << ' '
      //          << std::setw(8) << x[3] << ' '
      //          << std::setw(8) << x[4] << ' '
      //          << std::setw(8) << x[5] << ' '
      //          << std::setw(8) << x[6] << ' '
      //          << std::setw(8) << x[7] << std::dec << std::setfill(' ');
      //   // INFO() << "min_hashes: " << to_string(x);
      // }
      auto iter = std::min_element(min_hashes.cbegin(), min_hashes.cend());
      hash32_t min_hash_local = *iter;
      if (min_hash_local < min_hash) {
        min_hash = min_hash_local;
        min_nonce = min_nonces[std::distance(min_hashes.cbegin(), iter)];
      }

      clock_gettime(CLOCK_REALTIME, &iteration_finish);
      long iteration_sec = iteration_finish.tv_sec - iteration_start.tv_sec;
      long iteration_nsec = iteration_finish.tv_nsec - iteration_start.tv_nsec;
      if (iteration_start.tv_nsec > iteration_finish.tv_nsec) {
        --iteration_sec;
        iteration_nsec += 1000000000ULL;
      }
      double iteration_took = double(iteration_sec) + double(iteration_nsec) / 1e9;

      offset += batch_size;
      if (1) {
        auto min_hash_sofar = min_hash;
        std::reverse(min_hash_sofar.begin(), min_hash_sofar.end());
        INFO() << "min hash so far: " << prettify_hash(to_string(min_hash_sofar))
               << std::fixed << std::setprecision(3)
               << " took " << iteration_took << 's'
               << ' ' << (float(offset) / float(nonce_iterations)) << ' '
               << ((nonce_ends[offset + (batch_size - 1)] - nonce_begins[offset] + 1) / iteration_took / 1e6)
               << "MiH/s";
      }
    }

    clock_gettime(CLOCK_REALTIME, &hashing_finish);
    long hashing_sec = hashing_finish.tv_sec - hashing_start.tv_sec;
    long hashing_nsec = hashing_finish.tv_nsec - hashing_start.tv_nsec;
    if (hashing_start.tv_nsec > hashing_finish.tv_nsec) {
      --hashing_sec;
      hashing_nsec += 1000000000ULL;
    }
    double hashing_took = double(hashing_sec) + double(hashing_nsec) / 1e9;

    INFO() << "took " << hashing_took << 's'
           << " hashrate " << std::fixed << std::setprecision(3)
           << ((nonce_end - nonce_begin) / hashing_took / 1e6) << " MiH/s";
    std::reverse(min_hash.begin(), min_hash.end());
    // for (unsigned i = 0; i < 8; ++i)
    //   min_hash[i] = htonl(min_hash[i]);
    
    return std::make_pair(std::move(min_hash), min_nonce);
  }
 private:
  opencl::context&     ctx_;
  opencl::base_program program_;

  cl_kernel hasher_;
  cl_mem mem_target_hash_;
  cl_mem mem_message_;
  cl_mem mem_message_len_;
  cl_mem mem_nonce_begins_;
  cl_mem mem_nonce_ends_;
  cl_mem mem_min_hashes_;
  cl_mem mem_min_nonces_;
};
