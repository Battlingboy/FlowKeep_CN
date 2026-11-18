#ifndef FK_FEATURE_VALIDATION_H
#define FK_FEATURE_VALIDATION_H
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace flowkeep {
// Same acceptance relation as isfinite, or finite positive zero for controls.
// No floating-point arithmetic, type punning, fast-math or skipped elements.
// Integer reduction allows the compiler to vectorize the full validation.
inline bool FeatureValuesValidBulk(const float *values, size_t count,
                                   bool positive_zero = false) noexcept {
    static_assert(sizeof(float) == sizeof(uint32_t) &&
                  std::numeric_limits<float>::is_iec559, "IEEE binary32 required");
    uint32_t invalid = 0;
    if (positive_zero) {
        for (size_t i = 0; i < count; ++i) {
            uint32_t bits;
            std::memcpy(&bits, values + i, sizeof(bits));
            invalid |= bits;
        }
    } else {
        for (size_t i = 0; i < count; ++i) {
            uint32_t bits;
            std::memcpy(&bits, values + i, sizeof(bits));
            invalid |= ((bits & UINT32_C(0x7f800000)) == UINT32_C(0x7f800000));
        }
    }
    return invalid == 0;
}
inline int FeatureValidationMode() noexcept {
    static const int mode = [] {
        const char *v = std::getenv("FK_BULK_FEATURE_VALIDATE");
        if (!v || !std::strcmp(v, "0")) return 0;
        return !std::strcmp(v, "1") ? 1 : -1;
    }();
    return mode;
}
inline bool FeatureValuesValid(const float *values, size_t count,
                              bool positive_zero = false) noexcept {
    const int mode = FeatureValidationMode();
    if (mode < 0) return false;
    if (mode) return FeatureValuesValidBulk(values, count, positive_zero);
    for (size_t i = 0; i < count; ++i)
        if (!std::isfinite(values[i]) ||
            (positive_zero && (values[i] != 0.0f || std::signbit(values[i]))))
            return false;
    return true;
}
} // namespace flowkeep
#endif
