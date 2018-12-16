#pragma once

#include "common/types.hxx"
#include "common/profile.hxx"
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
    common::profile hashing_time;
    common::profile iteration_time;
    hashing_time.start();

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

    for (unsigned offset = 0; offset < nonce_iterations; ) {
      iteration_time.start();

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
             << ((nonce_ends[offset + (batch_size - 1)] - nonce_begins[offset] + 1) / iteration_took / 1e6)
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
  cl_mem mem_target_hash_;
  cl_mem mem_message_;
  cl_mem mem_message_len_;
  cl_mem mem_nonce_begins_;
  cl_mem mem_nonce_ends_;
  cl_mem mem_min_hashes_;
  cl_mem mem_min_nonces_;
};
