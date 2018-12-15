#pragma once

#include <ostream>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include "common/logging.hxx"

namespace opencl {

struct base_program;
struct context;

struct base_program {
  base_program(cl_program program = nullptr): program_{program} {}
  base_program(base_program const&) = delete;
  base_program(base_program&& other):
      program_{other.program_} {
    other.program_ = nullptr;
  }
  base_program& operator = (base_program const&) = delete;
  base_program& operator = (base_program&& other) {
    program_ = other.program_;
    other.program_ = nullptr;
    return *this;
  }
  ~base_program() {
    if (program_) {
      auto rv = clReleaseProgram(program_);
      if (rv != CL_SUCCESS)
        ERROR() << "clReleaseProgram failed";
    }
  }

  static void pfn_notify(cl_program, void *user_data);

  cl_program program() const {
    return program_;
  }

 private:
  cl_program program_;
};

struct context {
  cl_platform_id   platform_;
  cl_device_id     device_;
  cl_context       ctx_;
  cl_command_queue command_queue_;

  context() = default;
  context(context const&) = delete;
  context(context&&) = delete;
  ~context() = default;

  static void pfn_notify(char const* errinfo, void const* private_info,
                         std::size_t cb, void* user_data);

  void init(unsigned platform_id, unsigned device_id) {
    cl_platform_id platforms[8];
    cl_device_id devices[8];   
    cl_uint n_devices;
    cl_uint n_platforms;
    cl_int rv;

    rv = clGetPlatformIDs(sizeof(platforms) / sizeof(platforms[0]), platforms, &n_platforms);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clGetPlatformIDs failed");
    if (platform_id >= n_platforms)
      throw std::runtime_error("platform_id is too large");
    platform_ = platforms[platform_id];

    rv = clGetDeviceIDs(platform_, CL_DEVICE_TYPE_ALL,
                        sizeof(devices) / sizeof(devices[0]), 
                        devices, &n_devices);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clGetDeviceIDs failed");
    if (device_id >= n_devices)
      throw std::runtime_error("device_id is too large");
    device_ = devices[device_id];

    ctx_ = clCreateContext(nullptr, 1, &device_, &context::pfn_notify, this, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateContext failed");

    command_queue_ = clCreateCommandQueue(ctx_, device_, 0, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateContext failed");
  }

  void cleanup() {
    cl_int rv;
    rv = clFlush(command_queue_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clFlush failed");
    rv = clFinish(command_queue_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clFinish failed");
    rv = clReleaseCommandQueue(command_queue_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clReleaseCommandQueue failed");
    rv = clReleaseContext(ctx_);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clReleaseContext failed");
  }

  cl_context ctx() const {
    return ctx_;
  }

  cl_command_queue command_queue() const {
    return command_queue_;
  }

  base_program make_program(char const* source, std::size_t len) {
    cl_int rv;
    cl_program prog;
    prog = clCreateProgramWithSource(ctx_, 1, &source, &len, &rv);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clCreateProgramWithSource failed");

    rv = clBuildProgram(prog, 1, &device_, "-Werror", &base_program::pfn_notify, this);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clBuildProgram failed");

    return {prog};
  }
};

void base_program::pfn_notify(cl_program, void* user_data) {
  ERROR() << "program::pfn_notify";
}

void context::pfn_notify(char const* errinfo, void const* private_info,
                                std::size_t cb, void* user_data) {
  ERROR() << "context::pfn_notify: " << errinfo;
}

template <typename T>
std::size_t get_device_info(cl_device_id& device,
                            cl_device_info param_name,
                            T&& param_value,
                            std::size_t param_size) {
  cl_int rv;
  std::size_t size_ret;
  rv = clGetDeviceInfo(
      device, param_name,
      param_size, &param_value, &size_ret);
  if (rv != CL_SUCCESS)
    throw std::runtime_error("clGetDeviceInfo failed");
  return size_ret;
}

template <typename T>
std::size_t get_device_info(cl_device_id& device,
                            cl_device_info param_name,
                            T&& param_value) {
  cl_int rv;
  std::size_t size_ret;
  rv = clGetDeviceInfo(
      device, param_name,
      sizeof(param_value), &param_value, &size_ret);
  if (rv != CL_SUCCESS)
    throw std::runtime_error("clGetDeviceInfo failed");
  return size_ret;
}

template <typename CharT, std::size_t N>
std::size_t get_device_info(cl_device_id& device,
                            cl_device_info param_name,
                            CharT (&param_value)[N]) {
  cl_int rv;
  std::size_t size_ret;
  rv = clGetDeviceInfo(
      device, param_name,
      sizeof(param_value), &param_value, &size_ret);
  if (rv != CL_SUCCESS)
    throw std::runtime_error("clGetDeviceInfo failed");
  return size_ret;
}

std::ostream& print_info(std::ostream& os) {
  // https://www.khronos.org/registry/OpenCL/sdk/1.0/docs/man/xhtml/clGetDeviceInfo.html
  cl_platform_id platform_id[8];
  cl_device_id device_id[8];   
  cl_uint n_devices;
  cl_uint n_platforms;
  cl_int rv;

  rv = clGetPlatformIDs(sizeof(platform_id) / sizeof(platform_id[0]),
                        platform_id, &n_platforms);
  if (rv != CL_SUCCESS)
    throw std::runtime_error("clGetPlatformIDs failed");
  os << "Number of platforms: " << n_platforms << '\n';

  for (unsigned i = 0; i < n_platforms; ++i) {
    os << "Platform " << i << ":\n";
    rv = clGetDeviceIDs(platform_id[i], CL_DEVICE_TYPE_ALL,
                        sizeof(device_id) / sizeof(device_id[0]), 
                        device_id, &n_devices);
    if (rv != CL_SUCCESS)
      throw std::runtime_error("clGetPlatformIDs failed");
    os << "Number of devices: " << n_devices << '\n';

    for (unsigned j = 0; j < n_devices; ++j) {
      auto& device = device_id[j];
      char     string_value[1024];
      cl_uint  uint_value;
      cl_ulong ulong_value;
      cl_bool  bool_value;
      size_t   size_value;

      os << '\n';

      get_device_info(device, CL_DEVICE_NAME, string_value);
      os << "Device name: " << string_value << '\n';

      get_device_info(device, CL_DEVICE_VERSION, string_value);
      os << "Device version: " << string_value << '\n';

      get_device_info(device, CL_DRIVER_VERSION, string_value);
      os << "Driver version: " << string_value << '\n';

      get_device_info(device, CL_DEVICE_VENDOR, string_value);
      os << "Driver vendor: " << string_value << '\n';

      cl_device_type device_type;
      get_device_info(device, CL_DEVICE_TYPE, device_type);
      os << "Device type: ";
      switch (device_type) {
        case CL_DEVICE_TYPE_CPU:
          os << "CL_DEVICE_TYPE_CPU";
          break;
        case CL_DEVICE_TYPE_GPU:
          os << "CL_DEVICE_TYPE_GPU";
          break;
        case CL_DEVICE_TYPE_ACCELERATOR:
          os << "CL_DEVICE_TYPE_ACCELERATOR";
          break;
        case CL_DEVICE_TYPE_DEFAULT:
          os << "CL_DEVICE_TYPE_DEFAULT";
          break;
      }
      os << '\n';

      get_device_info(device, CL_DEVICE_ADDRESS_BITS, uint_value);
      os << "The default compute device address space size specified as an unsigned integer value in bits: "
         << uint_value << '\n';
      
      get_device_info(device, CL_DEVICE_AVAILABLE, bool_value);
      os << "Available: " << (bool_value ? "true" : "false") << '\n';

      get_device_info(device, CL_DEVICE_ENDIAN_LITTLE, bool_value);
      os << "Little endian: " << (bool_value ? "true" : "false") << '\n';      

      get_device_info(device, CL_DEVICE_ERROR_CORRECTION_SUPPORT, bool_value);
      os << "Error correction: " << (bool_value ? "true" : "false") << '\n';      

      cl_device_exec_capabilities exec_cap;
      get_device_info(device, CL_DEVICE_EXECUTION_CAPABILITIES, exec_cap);
      os << "Execution capabilities: ";
      if (exec_cap & CL_EXEC_KERNEL)
        os << "CL_EXEC_KERNEL ";
      if (exec_cap & CL_EXEC_NATIVE_KERNEL)
        os << "CL_EXEC_NATIVE_KERNEL ";
      os << '\n';

      get_device_info(device, CL_DEVICE_EXTENSIONS, string_value);
      os << "Extensions: " << string_value << '\n';

      get_device_info(device, CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, ulong_value);
      os << "Size of global memory cache in bytes: " << ulong_value << '\n';      

      cl_device_mem_cache_type cache_type;
      get_device_info(device, CL_DEVICE_GLOBAL_MEM_CACHE_TYPE, cache_type);
      os << "Type of global memory cache supported: ";
      switch (cache_type) {
        case CL_NONE:
          os << "CL_NONE";
          break;
        case CL_READ_ONLY_CACHE:
          os << "CL_READ_ONLY_CACHE";
          break;
        case CL_READ_WRITE_CACHE:
          os << "CL_READ_WRITE_CACHE";
          break;
      };
      os << '\n';

      get_device_info(device, CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE, uint_value);
      os << "Size of global memory cache line in bytes: " << uint_value << '\n';

      get_device_info(device, CL_DEVICE_GLOBAL_MEM_SIZE, ulong_value);
      os << "Size of global device memory in bytes: " << ulong_value << '\n';

      get_device_info(device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, ulong_value);
      os << "Max size of memory object allocation in bytes: " << ulong_value << '\n';

      get_device_info(device, CL_DEVICE_LOCAL_MEM_SIZE, ulong_value);
      os << "Size of local memory arena in bytes: " << ulong_value << '\n';

      cl_device_local_mem_type local_mem_type;
      get_device_info(device, CL_DEVICE_LOCAL_MEM_TYPE, local_mem_type);
      os << "Type of local memory supported: ";
      switch (local_mem_type) {
        case CL_LOCAL:
          os << "CL_LOCAL\n";
          break;
        case CL_GLOBAL:
          os << "CL_GLOBAL\n";
          break;
      }

      std::pair<unsigned, char const*> kvs[] = {
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR"},
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT"},
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT"},
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG"},
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT"},
          {CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE, "CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE"}};
      for (auto [k, v] : kvs) {
        get_device_info(device, k, uint_value);
        os << v << ": " << uint_value << '\n';
      }

      get_device_info(device, CL_DEVICE_MAX_COMPUTE_UNITS, uint_value);
      os << "The number of parallel compute cores: " << uint_value << '\n';

      get_device_info(device, CL_DEVICE_MAX_CONSTANT_ARGS, uint_value);
      os << "Max number of arguments declared with the __constant qualifier in a kernel: " << uint_value << '\n';

      get_device_info(device, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, ulong_value);
      os << "Max size in bytes of a constant buffer allocation: " << ulong_value << '\n';

      get_device_info(device, CL_DEVICE_PROFILING_TIMER_RESOLUTION, size_value);
      os << "Resolution of device timer: " << size_value << '\n';

      cl_bool image_support;
      get_device_info(device, CL_DEVICE_IMAGE_SUPPORT, image_support);
      os << "Image support: " << (image_support ? "true" : "false") << '\n';

      cl_command_queue_properties queue_props;
      get_device_info(device, CL_DEVICE_QUEUE_PROPERTIES, queue_props);
      os << "Command-queue properties supported: ";
      if (queue_props & CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE)
        os << "CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE ";
      if (queue_props & CL_QUEUE_PROFILING_ENABLE)
        os << "CL_QUEUE_PROFILING_ENABLE ";
      os << '\n';
    }
  }

  return os;
}

}
