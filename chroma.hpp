#include <gmp.h>
#include <iostream>

#define CHROMA_CTORTRAIT(Name)                                                 \
  Name(Name &) = delete;                                                       \
  Name(Name &&) = delete;                                                      \
  Name &operator=(const Name &) = delete;                                      \
  Name &&operator=(const Name &&) = delete

namespace chroma {

class ModN {
public:
  virtual ~ModN() = default;
  ModN() = default;
  CHROMA_CTORTRAIT(ModN);
};

class EulerTPhi {
public:
  virtual ~EulerTPhi() = default;
  EulerTPhi() = default;
  CHROMA_CTORTRAIT(EulerTPhi);
};

class Seed {
public:
  static std::unique_ptr<Seed> MakePair(std::size_t left, std::size_t right);

  virtual std::unique_ptr<ModN> MakeModN() const noexcept = 0;
  virtual std::unique_ptr<EulerTPhi> MakeEulerTPhi() const noexcept = 0;

  virtual ~Seed() = default;
  Seed() = default;
  CHROMA_CTORTRAIT(Seed);
};

class PairSeed : public Seed {
public:
  explicit PairSeed(std::size_t left, std::size_t right)
      : left_{left}, right_{right} {}

  std::unique_ptr<ModN> MakeModN() const noexcept final;
  std::unique_ptr<EulerTPhi> MakeEulerTPhi() const noexcept final;

  PairSeed() = delete;
  CHROMA_CTORTRAIT(PairSeed);

private:
  std::size_t left_, right_;
};

std::unique_ptr<Seed> Seed::MakePair(std::size_t left, std::size_t right) {
  return std::make_unique<PairSeed>(left, right);
}

class TModN : public ModN {
public:
  TModN(std::size_t a, std::size_t b) : value_{a * b} {}

  std::size_t value() const noexcept { return value_; }

  TModN() = delete;
  CHROMA_CTORTRAIT(TModN);

private:
  std::size_t value_;
};

std::unique_ptr<ModN> PairSeed::MakeModN() const noexcept {
  return std::make_unique<TModN>(left_, right_);
}

class UEulerTPhi : public EulerTPhi {
public:
  explicit UEulerTPhi(std::size_t a, std::size_t b)
      : value_{(a - 1) * (b - 1)} {}

  std::size_t value() const noexcept { return value_; }

  UEulerTPhi() = delete;
  CHROMA_CTORTRAIT(UEulerTPhi);

private:
  std::size_t value_;
};

std::unique_ptr<EulerTPhi> PairSeed::MakeEulerTPhi() const noexcept {
  return std::make_unique<UEulerTPhi>(left_, right_);
}

class Cryptex {
public:
  static std::unique_ptr<Cryptex> Make(std::unique_ptr<ModN> &&modn,
                                       std::unique_ptr<EulerTPhi> &&eulertPhi);

  virtual std::size_t pubE() const noexcept = 0;
  virtual std::size_t pubN() const noexcept = 0;
  virtual std::size_t privD() const noexcept = 0;

  virtual std::size_t crypt(std::size_t c) const noexcept = 0;
  virtual std::size_t decrypt(std::size_t d) const noexcept = 0;

  virtual ~Cryptex() = default;
  Cryptex() = default;
  CHROMA_CTORTRAIT(Cryptex);
};

class AtomCryptex : public Cryptex {
public:
  explicit AtomCryptex(std::unique_ptr<ModN> &&modn,
                       std::unique_ptr<EulerTPhi> &&eulertPhi)
      : a_modn_{std::move(modn)}, a_eulertPhi_{std::move(eulertPhi)},
        modn_(ctoreval<TModN>(a_modn_)),
        eulertPhi_(ctoreval<UEulerTPhi>(a_eulertPhi_)) {
    n_ = modn_.value();
    phin_ = eulertPhi_.value();
    e_ = FindE();
    d_ = FindD();
  }

  std::size_t pubE() const noexcept final { return e_; }
  std::size_t pubN() const noexcept final { return n_; }
  std::size_t privD() const noexcept final { return d_; }

  std::size_t crypt(std::size_t c) const noexcept final {
    return powmod(c, e_, n_);
  }

  std::size_t decrypt(std::size_t d) const noexcept final {
    return powmod(d, d_, n_);
  }

  AtomCryptex() = delete;
  CHROMA_CTORTRAIT(AtomCryptex);

private:
  std::unique_ptr<ModN> a_modn_;
  std::unique_ptr<EulerTPhi> a_eulertPhi_;
  TModN &modn_;
  UEulerTPhi &eulertPhi_;

  std::size_t n_;
  std::size_t phin_;
  std::size_t e_;
  std::size_t d_;

  std::size_t FindE() {
    for (std::size_t e = 5; e < phin_; e++) {
      if (phin_ % e) {
        bool keep = true;
        for (std::size_t d = 2; d < e; d++) {
          if (!(e % d) && !(phin_ % d)) {
            keep = false;
            break;
          }
        }
        if (keep) {
          return e;
        }
      }
    }
    throw std::runtime_error("not-cop");
  }

  std::size_t FindD() {
    for (std::size_t d = 2; d < phin_; d++) {
      if ((d * e_) % phin_ == 1) {
        return d;
      }
    }
    throw std::runtime_error("not mod-mult");
  }

  template <class V, class W> static V &ctoreval(const std::unique_ptr<W> &p) {
    V *v;
    if ((v = dynamic_cast<V *>(p.get())) == nullptr) {
      throw std::bad_alloc();
    }
    return *v;
  }

  static std::size_t powmod(std::size_t e, std::size_t n,
                            std::size_t m) noexcept {
    mpz_t a, b, c;
    mpz_init(a);
    mpz_init(b);
    mpz_init(c);
    mpz_set_ui(a, e);
    mpz_pow_ui(b, a, n);
    mpz_mod_ui(c, b, m);
    std::size_t d = mpz_get_ui(c);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(c);
    return d;
  }
};

std::unique_ptr<Cryptex> Cryptex::Make(std::unique_ptr<ModN> &&modn,
                                       std::unique_ptr<EulerTPhi> &&eulertPhi) {
  return std::make_unique<AtomCryptex>(
      std::forward<std::unique_ptr<ModN>>(modn),
      std::forward<std::unique_ptr<EulerTPhi>>(eulertPhi));
}

} // namespace chroma
