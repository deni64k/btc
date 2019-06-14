#pragma once

#include <chrono>

#include "common/types.hxx"
#include "common/profile.hxx"
#include "opencl/opencl.hxx"

struct sha256_program {
  static constexpr std::size_t const max_batch_size = 256*1024;
  static constexpr std::size_t const nonce_step = 4 * 1024 + 512;
  static constexpr std::size_t const opencl_local_size = 64;

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

    mem_min_hashes_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY,
        sizeof(hash32_t) * max_batch_size,
        nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    mem_min_nonces_ = clCreateBuffer(
        ctx_.ctx(),
        CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY,
        sizeof(std::uint32_t) * max_batch_size,
        nullptr, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateBuffer failed");

    int i = 5;
    rv = clSetKernelArg(hasher_, i++, sizeof(hash32_t) * opencl_local_size, nullptr);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, i++, sizeof(std::uint32_t) * opencl_local_size, nullptr);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, i++, sizeof(mem_min_hashes_), &mem_min_hashes_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, i++, sizeof(mem_min_nonces_), &mem_min_nonces_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
  }

  ~sha256_program() {
    cl_int rv;
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
               std::array<std::uint32_t, 16> const& W, hash32_t& digest_hash,
               std::uint32_t nonce_begin,
               std::uint32_t nonce_end) {
    common::profile hashing_time;
    common::profile iteration_time;
    hashing_time.start();

    std::size_t nonce_iterations = (std::size_t{nonce_end - nonce_begin} + nonce_step - 1) / nonce_step;

    std::uint32_t min_nonce;
    hash32_t min_hash;
    std::fill(min_hash.begin(), min_hash.end(), 0xffffffff);

    std::uint32_t merkle_root, timestamp, target_bits;
    std::uint8_t const *message_ptr = message.data() + 64;
    merkle_root  = (*message_ptr++) << 24;
    merkle_root |= (*message_ptr++) << 16;
    merkle_root |= (*message_ptr++) <<  8;
    merkle_root |= (*message_ptr++) <<  0;
    timestamp    = (*message_ptr++) << 24;
    timestamp   |= (*message_ptr++) << 16;
    timestamp   |= (*message_ptr++) <<  8;
    timestamp   |= (*message_ptr++) <<  0;
    target_bits  = (*message_ptr++) << 24;
    target_bits |= (*message_ptr++) << 16;
    target_bits |= (*message_ptr++) <<  8;
    target_bits |= (*message_ptr++) <<  0;

    cl_int  rv;
    rv = clSetKernelArg(hasher_, 0, sizeof(merkle_root), &merkle_root);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 1, sizeof(timestamp), &timestamp);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 2, sizeof(target_bits), &target_bits);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");
    rv = clSetKernelArg(hasher_, 3, sizeof(digest_hash), digest_hash.data());
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clSetKernelArg failed");

    std::vector<hash32_t> min_hashes;
    std::vector<std::uint32_t> min_nonces;
    min_hashes.reserve(opencl_local_size);
    min_nonces.reserve(opencl_local_size);
    for (unsigned offset = 0; offset < nonce_iterations; ) {
      iteration_time.start();

      unsigned rem = nonce_iterations - offset;
      unsigned batch_size = std::min<unsigned>(rem, max_batch_size);

      rv = clSetKernelArg(hasher_, 4, sizeof(offset), &offset);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clSetKernelArg failed");

      std::size_t global_item_size = batch_size;
      std::size_t local_item_size  = opencl_local_size;
      if (global_item_size < max_batch_size) {
        if (global_item_size < local_item_size) {
          local_item_size = 1;
        } else {
          if (batch_size % local_item_size > 0)
            ++nonce_iterations;
          batch_size = std::size_t(batch_size / local_item_size) * local_item_size;
          global_item_size = batch_size;
        }
      }
      rv = clEnqueueNDRangeKernel(ctx_.command_queue(), hasher_, 1,
                                  nullptr, &global_item_size, &local_item_size,
                                  0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueNDRangeKernel failed");

      min_hashes.resize(batch_size / local_item_size);
      rv = clEnqueueReadBuffer(ctx_.command_queue(), mem_min_hashes_, CL_FALSE, 0, 
                               min_hashes.size() * sizeof(min_hashes[0]), min_hashes.data(),
                               0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueReadBuffer failed");

      min_nonces.resize(batch_size / local_item_size);
      rv = clEnqueueReadBuffer(ctx_.command_queue(), mem_min_nonces_, CL_FALSE, 0, 
                               min_nonces.size() * sizeof(min_nonces[0]), min_nonces.data(),
                               0, nullptr, nullptr);
      if (rv != CL_SUCCESS)
        throw std::runtime_error("clEnqueueReadBuffer failed");

      clFinish(ctx_.command_queue());

      // using namespace std::chrono_literals;
      // std::this_thread::sleep_for(100ms);

      auto iter = std::min_element(min_hashes.cbegin(), min_hashes.cend());
      hash32_t min_hash_local = *iter;
      if (min_hash_local < min_hash) {
        min_hash = min_hash_local;
        min_nonce = min_nonces[std::distance(min_hashes.cbegin(), iter)];
      }

      offset += batch_size;

      iteration_time.finish();
      double iteration_took = iteration_time.seconds();

      auto min_hash_sofar = min_hash;
      std::reverse(min_hash_sofar.begin(), min_hash_sofar.end());
      INFO() << std::fixed << std::setprecision(3)
             << "iteration took "
             << iteration_took << 's'
             << "\tmin hash so far: "
             << prettify_hash(to_string(min_hash_sofar))
             << "\tprogress: "
             << (float(offset) / float(nonce_iterations))
             << "\thashrate: "
             << (nonce_step * batch_size / iteration_took / 1e6)
             << "MiH/s";

      if (compare_hashes(min_hash_sofar, target_hash) <= 0)
        break;
    }

    hashing_time.finish();
    double hashing_took = hashing_time.seconds();

    INFO() << "mining took " << hashing_took << 's'
           << "\thashrate: " << std::fixed << std::setprecision(3)
           << ((nonce_end - nonce_begin) / hashing_took / 1e6) << " MiH/s";
    std::reverse(min_hash.begin(), min_hash.end());
    
    return std::make_pair(std::move(min_hash), min_nonce);
  }
 private:
  opencl::context&     ctx_;
  opencl::base_program program_;

  cl_kernel hasher_;
  cl_mem mem_min_hashes_;
  cl_mem mem_min_nonces_;
};
