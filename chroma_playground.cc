#include <gtest/gtest.h>

#include "chroma.hpp"

TEST(ChromeTest, Direct) {
  auto seed = chroma::Seed::MakePair(11, 17);
  auto modn = seed->MakeModN();
  auto eulertphi = seed->MakeEulerTPhi();

  auto cryptex = chroma::Cryptex::Make(std::move(modn), std::move(eulertphi));

  EXPECT_EQ(cryptex->pubE(), 7);
  EXPECT_EQ(cryptex->pubN(), 187);
  EXPECT_EQ(cryptex->privD(), 23);

  EXPECT_EQ(cryptex->crypt(8), 134);
  EXPECT_EQ(cryptex->decrypt(134), 8);
}
