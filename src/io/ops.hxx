#pragma once

#include <array>

#include "common/types.hxx"
#include "proto/commands.hxx"

template <typename base_ops, typename T>
struct io_ops {
  static void read(base_ops& io, T& o) {
    using o_type = std::remove_cvref_t<T>;
    io.read_impl(reinterpret_cast<char *>(&o), sizeof(o_type));
  }
  static void write(base_ops& io, T const& o) {
    using o_type = std::remove_cvref_t<T>;
    io.write_impl(reinterpret_cast<char const*>(&o), sizeof(o_type));
  }
};

template <typename base_ops, typename T, std::size_t N>
struct io_ops<base_ops, std::array<T, N>> {
  static void read(base_ops& io, std::array<T, N>& o) {
    io.read_impl(reinterpret_cast<char *>(&o.front()), sizeof(T) * N);
  }
  static void write(base_ops& io, std::array<T, N> const& o) {
    io.write_impl(reinterpret_cast<char const*>(&o.front()), sizeof(T) * N);
  }
};

template <typename base_ops>
struct io_ops<base_ops, be_uint16_t> {
  static void read(base_ops& io, be_uint16_t& o) {
    io.read_impl((char*)&o.num, sizeof(o.num));
    o.num = ntohs(o.num);
  }

  static void write(base_ops& io, be_uint16_t const o) {
    std::uint16_t num = htons(o.num);
    io.write_impl((char*)&num, sizeof(num));
  }
};

template <typename base_ops>
struct io_ops<base_ops, var_int> {
  static void read(base_ops& io, var_int& o) {
    std::uint8_t prefix;
    io.read_impl((char*)&prefix, 1);
    if (prefix < 0xfd) {
      o.num = prefix;
    } else if (prefix == 0xfd) {
      std::uint16_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else if (prefix == 0xfe) {
      std::uint32_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else if (prefix == 0xff) {
      std::uint64_t num;
      io.read_impl((char*)&num, sizeof(num));
      o.num = num;
    } else {
      throw std::runtime_error("unknown prefix in var_int");
    }
  }

  static void write(base_ops& io, var_int const o) {
    if (o.num < 0xfd) {
      std::uint8_t num = o.num;
      io.write_impl((char const*)&num, sizeof(num));
    } else if (o.num <= 0xffff) {
      std::uint8_t prefix = 0xfd;
      std::uint16_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    } else if (o.num <= 0xffffffff) {
      std::uint8_t prefix = 0xfe;
      std::uint32_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    } else {
      std::uint8_t prefix = 0xff;
      std::uint64_t num = o.num;
      io.write_impl((char const*)&prefix, sizeof(prefix));
      io.write_impl((char const*)&num, sizeof(num));
    }
  }
};

template <typename base_ops>
struct io_ops<base_ops, var_str> {
  static void read(base_ops& io, var_str& o) {
    var_int len;
    io_ops<base_ops, var_int>::read(io, len);
    o.resize(len.num);
    if (o.empty())
      return;

    io.read_impl(reinterpret_cast<char*>(&o.front()), len.num);
  }

  static void write(base_ops& io, var_str const& o) {
    io_ops<base_ops, var_int>::write(io, var_int{o.size()});
    if (o.empty())
      return;
    
    io.write_impl(reinterpret_cast<char const*>(&o.front()), o.size());
  }
};

template <typename base_ops, typename T>
struct io_ops<base_ops, std::vector<T>> {
  static void read(base_ops& io, std::vector<T>& o) {
    var_int len;
    io_ops<base_ops, var_int>::read(io, len);
    o.resize(len.num);
    if (o.empty())
      return;

    for (auto& e : o) {
      io_ops<base_ops, T>::read(io, e);
    }
  }

  static void write(base_ops& io, std::vector<T> const& o) {
    io_ops<base_ops, var_int>::write(io, var_int{o.size()});
    if (o.empty())
      return;
    
    for (auto const& e : o) {
      io_ops<base_ops, T>::write(io, e);
    }
  }
};

template <typename base_ops>
struct io_ops<base_ops, proto::tx> {
  static void read(base_ops& io, proto::tx& o) {
    io_ops<base_ops, decltype(o.version)>::read(io, o.version);
    bool has_witnesses = false;
    var_int len;
    io_ops<base_ops, decltype(len)>::read(io, len);
    if (len.num == 0) {
      has_witnesses = true;
      char c;
      io_ops<base_ops, decltype(c)>::read(io, c);
      io_ops<base_ops, decltype(len)>::read(io, len);
    }
    for (unsigned i = 0; i < len.num; ++i) {
      proto::tx_in tx;
      io_ops<base_ops, decltype(tx)>::read(io, tx);
      o.txs_in.push_back(std::move(tx));
    }
    io_ops<base_ops, decltype(o.txs_out)>::read(io, o.txs_out);
    if (has_witnesses) {
      io_ops<base_ops, decltype(o.tx_witnesses)>::read(io, o.tx_witnesses);
    }
    io_ops<base_ops, decltype(o.lock_time)>::read(io, o.lock_time);
  }

  static void write(base_ops& io, proto::tx const& o) {
    bool has_witnesses = !o.tx_witnesses.empty();
    io_ops<base_ops, decltype(o.version)>::write(io, o.version);
    if (has_witnesses) {
      std::array<char, 2> flag = {0, 1};
      io_ops<base_ops, decltype(flag)>::write(io, flag);
    }
    io_ops<base_ops, decltype(o.txs_in)>::write(io, o.txs_in);
    io_ops<base_ops, decltype(o.txs_out)>::write(io, o.txs_out);
    if (has_witnesses)
      io_ops<base_ops, decltype(o.tx_witnesses)>::write(io, o.tx_witnesses);
    io_ops<base_ops, decltype(o.lock_time)>::write(io, o.lock_time);
  }
};

template <typename base_ops, SerDes T>
struct io_ops<base_ops, T> {
  template <std::size_t ...Is>
  static void read_details(base_ops& io, T& o, std::index_sequence<Is...>) {
    auto tupl = o.tuple();
    ((io.template read<std::remove_cvref_t<decltype(std::get<Is>(tupl))>>(
        std::get<Is>(tupl))), ...);
  }
  static void read(base_ops& io, T& o) {
    read_details(io, o, std::make_index_sequence<std::tuple_size_v<decltype(o.tuple())>>{});
  }

  template <std::size_t ...Is>
  static void write_details(base_ops& io, T const& o, std::index_sequence<Is...>) {
    auto tupl = o.tuple();
    ((io.template write<std::remove_cvref_t<decltype(std::get<Is>(tupl))>>(
        std::get<Is>(tupl))), ...);
  }
  static void write(base_ops& io, T const& o) {
    write_details(io, o, std::make_index_sequence<std::tuple_size_v<decltype(o.tuple())>>{});
  }
};

struct socket_ops {
  socket_ops(int sock): sock_{sock} {}

  template <typename T> void read(T& o) {
    TRACE();
    io_ops<socket_ops, T>::read(*this, o);
  }
  template <typename T> void write(T const& o) {
    TRACE();
    io_ops<socket_ops, T>::write(*this, o);
  }

  void read_impl(char* p, std::size_t s) {
    while (s > 0) {
      int rv = ::read(sock_, p, s);
      if (rv <= 0)
        throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
      s -= rv;
      p += rv;
    }
  }
  void write_impl(char const* p, std::size_t s) {
    while (s > 0) {
      int rv = ::write(sock_, p, s);
      if (rv <= 0)
        throw std::system_error(std::make_error_code(static_cast<std::errc>(errno)));
      s -= rv;
      p += rv;
    }
  }

 private:
  int sock_;
};

struct ostream_ops {
  ostream_ops(std::ostream &os): os_{os} {}

  template <typename T> void write(T const& o) {
    TRACE();
    io_ops<ostream_ops, T>::write(*this, o);
  }

  void write_impl(char const* p, std::size_t s) {
    os_.write(p, s);
  }

 private:
  std::ostream &os_;
};

template <SerDes T>
void from_socket(int sock, T& payload) {
  socket_ops ops(sock);
  ops.read(payload);
}

template <SerDes T>
void to_socket(int sock, T const& payload) {
  socket_ops ops(sock);
  ops.write(payload);
}

template <SerDes T>
void to_stream(std::ostream& os, T const& payload) {
  ostream_ops ops(os);
  ops.write(payload);
}
