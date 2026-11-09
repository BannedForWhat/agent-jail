#pragma once

#include <cstdint>

struct LandlockPolicyConfig {
    bool allow_prompt_mesh_socket{true};
};

// Применение политики Landlock LSM внутри песочницы (после pivot_root)
// Возвращает true при успехе или если Landlock отключен в ядре (graceful pass)
bool apply_landlock_policy(const LandlockPolicyConfig& config) noexcept;
