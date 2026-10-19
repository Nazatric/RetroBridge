#include "retrobridge/arm32_interpreter.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>

namespace retrobridge::runtime {
namespace {

constexpr std::uint32_t kCpsrN = 1U << 31U;
constexpr std::uint32_t kCpsrZ = 1U << 30U;
constexpr std::uint32_t kCpsrC = 1U << 29U;
constexpr std::uint32_t kCpsrV = 1U << 28U;
constexpr std::uint32_t kCpsrThumb = 1U << 5U;
constexpr std::uint32_t kCpsrNzcv = kCpsrN | kCpsrZ | kCpsrC | kCpsrV;

struct StepResult final {
    GuestHookAction action = GuestHookAction::Continue;
    std::string diagnostic;
};

[[nodiscard]] StepResult fault(std::string diagnostic) {
    return {GuestHookAction::Fault, std::move(diagnostic)};
}

[[nodiscard]] std::int64_t sign_extend(std::uint32_t value, unsigned bit_count) noexcept {
    const auto range = std::uint64_t{1} << bit_count;
    const auto sign_bit = range >> 1U;
    const auto normalized = static_cast<std::uint64_t>(value) & (range - 1U);
    if ((normalized & sign_bit) == 0) return static_cast<std::int64_t>(normalized);
    return static_cast<std::int64_t>(normalized) - static_cast<std::int64_t>(range);
}

[[nodiscard]] bool flag(std::uint32_t cpsr, std::uint32_t mask) noexcept {
    return (cpsr & mask) != 0;
}

[[nodiscard]] bool condition_passed(std::uint32_t cpsr, std::uint32_t condition) noexcept {
    const bool n = flag(cpsr, kCpsrN);
    const bool z = flag(cpsr, kCpsrZ);
    const bool c = flag(cpsr, kCpsrC);
    const bool v = flag(cpsr, kCpsrV);
    switch (condition & 0xfU) {
        case 0x0: return z;
        case 0x1: return !z;
        case 0x2: return c;
        case 0x3: return !c;
        case 0x4: return n;
        case 0x5: return !n;
        case 0x6: return v;
        case 0x7: return !v;
        case 0x8: return c && !z;
        case 0x9: return !c || z;
        case 0xa: return n == v;
        case 0xb: return n != v;
        case 0xc: return !z && n == v;
        case 0xd: return z || n != v;
        case 0xe: return true;
        default: return false;
    }
}

void set_flag(std::uint32_t& cpsr, std::uint32_t mask, bool value) noexcept {
    if (value) cpsr |= mask;
    else cpsr &= ~mask;
}

void set_nz(std::uint32_t& cpsr, std::uint32_t result) noexcept {
    set_flag(cpsr, kCpsrN, (result & 0x80000000U) != 0);
    set_flag(cpsr, kCpsrZ, result == 0);
}

std::uint32_t add_flags(std::uint32_t& cpsr, std::uint32_t left, std::uint32_t right, bool carry_in = false) noexcept {
    const auto carry = carry_in ? 1ULL : 0ULL;
    const auto wide = static_cast<std::uint64_t>(left) + right + carry;
    const auto result = static_cast<std::uint32_t>(wide);
    const auto signed_result = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(left))
        + std::bit_cast<std::int32_t>(right) + static_cast<std::int64_t>(carry);
    set_nz(cpsr, result);
    set_flag(cpsr, kCpsrC, (wide >> 32U) != 0);
    set_flag(cpsr, kCpsrV, signed_result > std::numeric_limits<std::int32_t>::max()
        || signed_result < std::numeric_limits<std::int32_t>::min());
    return result;
}

std::uint32_t sub_flags(std::uint32_t& cpsr, std::uint32_t left, std::uint32_t right, bool borrow = false) noexcept {
    const auto subtrahend = static_cast<std::uint64_t>(right) + (borrow ? 1ULL : 0ULL);
    const auto result = static_cast<std::uint32_t>(static_cast<std::uint64_t>(left) - subtrahend);
    const auto signed_result = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(left))
        - std::bit_cast<std::int32_t>(right) - static_cast<std::int64_t>(borrow);
    set_nz(cpsr, result);
    set_flag(cpsr, kCpsrC, static_cast<std::uint64_t>(left) >= subtrahend);
    set_flag(cpsr, kCpsrV, signed_result > std::numeric_limits<std::int32_t>::max()
        || signed_result < std::numeric_limits<std::int32_t>::min());
    return result;
}

struct ShiftResult final {
    std::uint32_t value;
    bool carry;
};

[[nodiscard]] ShiftResult shift_value(
    std::uint32_t value,
    unsigned type,
    unsigned amount,
    bool carry_in,
    bool immediate) noexcept {
    if (amount == 0 && !immediate) return {value, carry_in};
    switch (type & 3U) {
        case 0: // LSL
            if (amount == 0) return {value, carry_in};
            if (amount < 32) return {value << amount, ((value >> (32U - amount)) & 1U) != 0};
            if (amount == 32) return {0, (value & 1U) != 0};
            return {0, false};
        case 1: // LSR
            if (amount == 0 && immediate) amount = 32;
            if (amount < 32) return {value >> amount, ((value >> (amount - 1U)) & 1U) != 0};
            if (amount == 32) return {0, ((value >> 31U) & 1U) != 0};
            return {0, false};
        case 2: // ASR
            if (amount == 0 && immediate) amount = 32;
            if (amount >= 32) {
                const bool sign = (value & 0x80000000U) != 0;
                return {sign ? 0xffffffffU : 0U, sign};
            }
            return {static_cast<std::uint32_t>(std::bit_cast<std::int32_t>(value) >> amount),
                ((value >> (amount - 1U)) & 1U) != 0};
        default: // ROR / RRX
            if (amount == 0 && immediate) {
                return {(static_cast<std::uint32_t>(carry_in) << 31U) | (value >> 1U), (value & 1U) != 0};
            }
            amount &= 31U;
            if (amount == 0) return {value, (value >> 31U) != 0};
            return {std::rotr(value, static_cast<int>(amount)), ((value >> (amount - 1U)) & 1U) != 0};
    }
}

[[nodiscard]] std::uint32_t arm_register(
    const GuestCpuState32& state,
    unsigned index,
    std::uint32_t current_pc) noexcept {
    if (index == 15) return current_pc + 8U;
    return state.r[index & 15U];
}

[[nodiscard]] std::uint32_t thumb_register(
    const GuestCpuState32& state,
    unsigned index,
    std::uint32_t current_pc) noexcept {
    if (index == 15) return (current_pc + 4U) & ~3U;
    return state.r[index & 15U];
}

void branch_exchange(GuestCpuState32& state, std::uint32_t target) noexcept {
    if ((target & 1U) != 0) {
        state.cpsr |= kCpsrThumb;
        state.r[15] = target & ~1U;
    } else {
        state.cpsr &= ~kCpsrThumb;
        state.r[15] = target & ~3U;
    }
    state.thumb_it_state = 0;
}

[[nodiscard]] bool read_guest_value(
    const GuestMemory& memory,
    std::uint32_t address,
    unsigned byte_count,
    std::uint32_t& value,
    bool sign_extend_value = false) noexcept {
    if (byte_count == 1) {
        const auto byte = memory.read_u8(GuestAddress32{address});
        if (!byte.has_value()) return false;
        value = sign_extend_value && ((*byte & 0x80U) != 0)
            ? 0xffffff00U | *byte : *byte;
        return true;
    }
    if (byte_count == 2) {
        const auto halfword = memory.read_u16(GuestAddress32{address});
        if (!halfword.has_value()) return false;
        value = sign_extend_value && ((*halfword & 0x8000U) != 0)
            ? 0xffff0000U | *halfword : *halfword;
        return true;
    }
    const auto word = memory.read_u32(GuestAddress32{address});
    if (!word.has_value()) return false;
    value = *word;
    return true;
}

[[nodiscard]] bool write_guest_value(
    GuestMemory& memory,
    std::uint32_t address,
    unsigned byte_count,
    std::uint32_t value) noexcept {
    if (byte_count == 1) {
        const std::array<std::byte, 1> bytes{static_cast<std::byte>(value & 0xffU)};
        return memory.write(GuestAddress32{address}, bytes);
    }
    if (byte_count == 2) return memory.write_u16(GuestAddress32{address}, static_cast<std::uint16_t>(value));
    return memory.write_u32(GuestAddress32{address}, value);
}

[[nodiscard]] std::uint32_t read_vfp_single(const GuestCpuState32& state, unsigned index) noexcept {
    const auto& q = state.q[index / 4U];
    const auto offset = (index % 4U) * 4U;
    std::uint32_t value = 0;
    for (unsigned byte = 0; byte < 4; ++byte) {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(q[offset + byte])) << (byte * 8U);
    }
    return value;
}

void write_vfp_single(GuestCpuState32& state, unsigned index, std::uint32_t value) noexcept {
    auto& q = state.q[index / 4U];
    const auto offset = (index % 4U) * 4U;
    for (unsigned byte = 0; byte < 4; ++byte) {
        q[offset + byte] = static_cast<std::byte>((value >> (byte * 8U)) & 0xffU);
    }
}

[[nodiscard]] std::uint64_t read_vfp_double(const GuestCpuState32& state, unsigned index) noexcept {
    const auto& q = state.q[index / 2U];
    const auto offset = (index % 2U) * 8U;
    std::uint64_t value = 0;
    for (unsigned byte = 0; byte < 8; ++byte) {
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(q[offset + byte])) << (byte * 8U);
    }
    return value;
}

void write_vfp_double(GuestCpuState32& state, unsigned index, std::uint64_t value) noexcept {
    auto& q = state.q[index / 2U];
    const auto offset = (index % 2U) * 8U;
    for (unsigned byte = 0; byte < 8; ++byte) {
        q[offset + byte] = static_cast<std::byte>((value >> (byte * 8U)) & 0xffU);
    }
}

[[nodiscard]] std::optional<StepResult> execute_vfp_data(
    GuestCpuState32& state,
    std::uint32_t instruction) {
    constexpr std::uint32_t kVfpEncodingMask = 0x0f000f10U;
    const auto encoded = instruction & kVfpEncodingMask;

    // VMOV between an ARM core register and an S register (VFP coprocessor 10).
    if (encoded == 0x0e000a10U) {
        const auto core_register = (instruction >> 12U) & 0xfU;
        const auto single_register = (((instruction >> 16U) & 0xfU) << 1U) | ((instruction >> 7U) & 1U);
        if (core_register == 15U) return fault("VFP VMOV using the ARM PC register is unpredictable");
        if ((instruction & (1U << 20U)) == 0) write_vfp_single(state, single_register, state.r[core_register]);
        else state.r[core_register] = read_vfp_single(state, single_register);
        return StepResult{};
    }

    const bool single_precision = encoded == 0x0e000a00U;
    const bool double_precision = encoded == 0x0e000b00U;
    if (!single_precision && !double_precision) return std::nullopt;

    // Bit 22 extends Vd (S or D register number); it is not part of the
    // scalar arithmetic opcode. Masking it lets odd/high destination registers
    // select the same operation as their neighboring even registers.
    const auto operation = ((instruction >> 20U) & 0xfU) & ~0x4U;
    const auto modifier = (instruction >> 6U) & 3U;
    enum class Arithmetic { Add, Subtract, Multiply, Divide };
    Arithmetic arithmetic{};
    if (operation == 3U && modifier == 0U) arithmetic = Arithmetic::Add;
    else if (operation == 3U && modifier == 1U) arithmetic = Arithmetic::Subtract;
    else if (operation == 2U && modifier == 0U) arithmetic = Arithmetic::Multiply;
    else if (operation == 8U && modifier == 0U) arithmetic = Arithmetic::Divide;
    else return fault("unsupported VFP scalar arithmetic opcode");

    const auto vd = (instruction >> 12U) & 0xfU;
    const auto vn = (instruction >> 16U) & 0xfU;
    const auto vm = instruction & 0xfU;
    if (single_precision) {
        const auto destination = (vd << 1U) | ((instruction >> 22U) & 1U);
        const auto left_register = (vn << 1U) | ((instruction >> 7U) & 1U);
        const auto right_register = (vm << 1U) | ((instruction >> 5U) & 1U);
        const auto left = std::bit_cast<float>(read_vfp_single(state, left_register));
        const auto right = std::bit_cast<float>(read_vfp_single(state, right_register));
        float result = 0.0F;
        switch (arithmetic) {
            case Arithmetic::Add: result = left + right; break;
            case Arithmetic::Subtract: result = left - right; break;
            case Arithmetic::Multiply: result = left * right; break;
            case Arithmetic::Divide: result = left / right; break;
        }
        write_vfp_single(state, destination, std::bit_cast<std::uint32_t>(result));
    } else {
        const auto destination = (((instruction >> 22U) & 1U) << 4U) | vd;
        const auto left_register = (((instruction >> 7U) & 1U) << 4U) | vn;
        const auto right_register = (((instruction >> 5U) & 1U) << 4U) | vm;
        const auto left = std::bit_cast<double>(read_vfp_double(state, left_register));
        const auto right = std::bit_cast<double>(read_vfp_double(state, right_register));
        double result = 0.0;
        switch (arithmetic) {
            case Arithmetic::Add: result = left + right; break;
            case Arithmetic::Subtract: result = left - right; break;
            case Arithmetic::Multiply: result = left * right; break;
            case Arithmetic::Divide: result = left / right; break;
        }
        write_vfp_double(state, destination, std::bit_cast<std::uint64_t>(result));
    }
    return StepResult{};
}

[[nodiscard]] StepResult execute_svc(
    GuestCpuState32& state,
    GuestMemory& memory,
    const GuestSvcHandler& handler,
    std::uint32_t immediate) {
    if (!handler) return fault("SVC executed without a registered guest syscall handler");
    const auto result = handler(state, immediate, memory);
    return {result.action, result.diagnostic};
}

[[nodiscard]] StepResult execute_arm(
    GuestCpuState32& state,
    GuestMemory& memory,
    const GuestSvcHandler& svc_handler,
    std::uint32_t pc,
    std::uint32_t instruction) {
    const auto condition = instruction >> 28U;
    if (condition != 0xfU && !condition_passed(state.cpsr, condition)) return {};
    if (const auto vfp_result = execute_vfp_data(state, instruction); vfp_result.has_value()) return *vfp_result;

    if ((instruction & 0x0ffffff0U) == 0x012fff10U
        || (instruction & 0x0ffffff0U) == 0x012fff30U) {
        const bool link = (instruction & 0x20U) != 0;
        const auto rm = instruction & 0xfU;
        const auto target = arm_register(state, rm, pc);
        if (link) state.r[14] = pc + 4U;
        branch_exchange(state, target);
        return {};
    }

    if ((instruction & 0x0f000000U) == 0x0f000000U) {
        return execute_svc(state, memory, svc_handler, instruction & 0x00ffffffU);
    }

    if (condition == 0xfU && (instruction & 0x0e000000U) == 0x0a000000U) {
        const auto immediate = ((instruction & 0x00ffffffU) << 2U) | (((instruction >> 24U) & 1U) << 1U);
        const auto displacement = sign_extend(immediate, 26U);
        state.r[14] = pc + 4U;
        state.cpsr |= kCpsrThumb;
        state.thumb_it_state = 0;
        state.r[15] = static_cast<std::uint32_t>(pc + 8U + displacement) & ~1U;
        return {};
    }

    if ((instruction & 0x0e000000U) == 0x0a000000U) {
        const auto immediate = sign_extend((instruction & 0x00ffffffU) << 2U, 26U);
        const bool link = (instruction & (1U << 24U)) != 0;
        if (link) state.r[14] = pc + 4U;
        state.r[15] = static_cast<std::uint32_t>(pc + 8U + immediate) & ~3U;
        state.thumb_it_state = 0;
        return {};
    }

    if ((instruction & 0x0fff0ff0U) == 0x016f0f10U) {
        const auto rd = (instruction >> 12U) & 0xfU;
        const auto rm = instruction & 0xfU;
        if (rd == 15U || rm == 15U) return fault("A32 CLZ uses an unpredictable PC operand");
        state.r[rd] = static_cast<std::uint32_t>(std::countl_zero(state.r[rm]));
        return {};
    }

    if ((instruction & 0x0ff00000U) == 0x03000000U
        || (instruction & 0x0ff00000U) == 0x03400000U) {
        const auto rd = (instruction >> 12U) & 0xfU;
        if (rd == 15) return fault("MOVW/MOVT targeting PC is undefined");
        const auto immediate = ((instruction >> 4U) & 0xf000U) | (instruction & 0x0fffU);
        if ((instruction & 0x00400000U) != 0) {
            state.r[rd] = (state.r[rd] & 0x0000ffffU) | (immediate << 16U);
        } else {
            state.r[rd] = (state.r[rd] & 0xffff0000U) | immediate;
        }
        return {};
    }

    const auto division_encoding = instruction & 0x0ff0f0f0U;
    if (division_encoding == 0x0710f010U || division_encoding == 0x0730f010U) {
        const bool signed_division = division_encoding == 0x0710f010U;
        const auto rd = (instruction >> 16U) & 0xfU;
        const auto divisor_register = (instruction >> 8U) & 0xfU;
        const auto dividend_register = instruction & 0xfU;
        if (rd == 15U || divisor_register == 15U || dividend_register == 15U) {
            return fault("A32 SDIV/UDIV using PC is unpredictable");
        }
        const auto divisor = state.r[divisor_register];
        const auto dividend = state.r[dividend_register];
        std::uint32_t quotient = 0;
        // ARM leaves division by zero architecturally UNPREDICTABLE. Keep the
        // interpreter deterministic and do not raise a host-language fault.
        if (divisor != 0) {
            if (signed_division) {
                const auto signed_dividend = std::bit_cast<std::int32_t>(dividend);
                const auto signed_divisor = std::bit_cast<std::int32_t>(divisor);
                if (signed_dividend == std::numeric_limits<std::int32_t>::min() && signed_divisor == -1) {
                    quotient = 0x80000000U;
                } else {
                    quotient = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(signed_dividend / signed_divisor));
                }
            } else {
                quotient = dividend / divisor;
            }
        }
        state.r[rd] = quotient;
        return {};
    }

    if ((instruction & 0x0f8000f0U) == 0x00800090U) {
        const bool signed_multiply = (instruction & (1U << 22U)) != 0;
        const bool accumulate = (instruction & (1U << 21U)) != 0;
        const bool set_flags = (instruction & (1U << 20U)) != 0;
        const auto rd_hi = (instruction >> 16U) & 0xfU;
        const auto rd_lo = (instruction >> 12U) & 0xfU;
        const auto rs = (instruction >> 8U) & 0xfU;
        const auto rm = instruction & 0xfU;
        if (rd_hi == 15U || rd_lo == 15U || rd_hi == rd_lo || rs == 15U || rm == 15U) {
            return fault("A32 long multiply uses an invalid PC or overlapping destination register");
        }
        std::uint64_t product = 0;
        if (signed_multiply) {
            const auto left = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(state.r[rm]));
            const auto right = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(state.r[rs]));
            product = static_cast<std::uint64_t>(left * right);
        } else {
            product = static_cast<std::uint64_t>(state.r[rm]) * state.r[rs];
        }
        if (accumulate) {
            const auto accumulator = (static_cast<std::uint64_t>(state.r[rd_hi]) << 32U) | state.r[rd_lo];
            product += accumulator;
        }
        state.r[rd_lo] = static_cast<std::uint32_t>(product);
        state.r[rd_hi] = static_cast<std::uint32_t>(product >> 32U);
        if (set_flags) {
            set_flag(state.cpsr, kCpsrN, (product >> 63U) != 0);
            set_flag(state.cpsr, kCpsrZ, product == 0);
        }
        return {};
    }

    if ((instruction & 0x0fc000f0U) == 0x00000090U) {
        const auto rd = (instruction >> 16U) & 0xfU;
        const auto rn = (instruction >> 12U) & 0xfU;
        const auto rs = (instruction >> 8U) & 0xfU;
        const auto rm = instruction & 0xfU;
        const auto product = arm_register(state, rm, pc) * arm_register(state, rs, pc);
        const auto result = product + (((instruction & (1U << 21U)) != 0)
            ? arm_register(state, rn, pc) : 0U);
        if (rd == 15) return fault("MUL/MLA targeting PC is unsupported");
        state.r[rd] = result;
        if ((instruction & (1U << 20U)) != 0) set_nz(state.cpsr, result);
        return {};
    }

    if ((instruction & 0x0e000000U) == 0x08000000U) {
        const bool pre_index = (instruction & (1U << 24U)) != 0;
        const bool increment = (instruction & (1U << 23U)) != 0;
        const bool user_registers = (instruction & (1U << 22U)) != 0;
        const bool writeback = (instruction & (1U << 21U)) != 0;
        const bool load = (instruction & (1U << 20U)) != 0;
        const auto base_register = (instruction >> 16U) & 0xfU;
        const auto register_list = instruction & 0xffffU;
        const auto register_count = static_cast<std::uint64_t>(std::popcount(register_list));
        if (register_count == 0) return fault("empty ARM LDM/STM register list is unsupported");
        if (user_registers) return fault("ARM LDM/STM user-register or exception-return forms are unsupported");
        if (base_register == 15U && writeback) return fault("ARM LDM/STM writeback using PC is unpredictable");
        if (writeback && (register_list & (1U << base_register)) != 0) {
            return fault("ARM LDM/STM writeback with the base register in the register list is unsupported");
        }
        const auto base = arm_register(state, base_register, pc);
        if ((base & 3U) != 0) return fault("ARM LDM/STM base address is not word-aligned");

        const auto transfer_bytes = register_count * 4U;
        const auto start = increment
            ? static_cast<std::uint64_t>(base) + (pre_index ? 4U : 0U)
            : static_cast<std::uint64_t>(base) - transfer_bytes + (pre_index ? 0U : 4U);
        const auto writeback_value = increment
            ? static_cast<std::uint64_t>(base) + transfer_bytes
            : static_cast<std::uint64_t>(base) - transfer_bytes;
        const auto address_space_end = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
        if (start > std::numeric_limits<std::uint32_t>::max() || start + transfer_bytes > address_space_end
            || (writeback && writeback_value > std::numeric_limits<std::uint32_t>::max())) {
            return fault("ARM LDM/STM address range wraps the 32-bit guest address space");
        }
        const auto access = load ? GuestPermission::Read : GuestPermission::Write;
        if (!memory.is_accessible(GuestAddress32{static_cast<std::uint32_t>(start)}, transfer_bytes, access)) {
            return fault(load ? "ARM LDM accessed unreadable guest memory" : "ARM STM accessed read-only guest memory");
        }

        std::array<std::uint32_t, 16> loaded_registers{};
        std::optional<std::uint32_t> loaded_pc;
        auto address = static_cast<std::uint32_t>(start);
        for (unsigned reg = 0; reg < 16; ++reg) {
            if ((register_list & (1U << reg)) == 0) continue;
            if (load) {
                const auto value = memory.read_u32(GuestAddress32{address});
                if (!value.has_value()) return fault("ARM LDM read failed after guest-range validation");
                if (reg == 15U) loaded_pc = *value;
                else loaded_registers[reg] = *value;
            } else {
                const auto value = reg == 15U ? pc + 12U : state.r[reg];
                if (!memory.write_u32(GuestAddress32{address}, value)) {
                    return fault("ARM STM write failed after guest-range validation");
                }
            }
            address += 4U;
        }
        if (load) {
            for (unsigned reg = 0; reg < 15; ++reg) {
                if ((register_list & (1U << reg)) != 0) state.r[reg] = loaded_registers[reg];
            }
            if (writeback) state.r[base_register] = static_cast<std::uint32_t>(writeback_value);
            if (loaded_pc.has_value()) {
                state.r[15] = *loaded_pc & ~3U;
                state.thumb_it_state = 0;
            }
        } else if (writeback) {
            state.r[base_register] = static_cast<std::uint32_t>(writeback_value);
        }
        return {};
    }

    if ((instruction & 0x0c000000U) == 0x04000000U) {
        const bool register_offset = (instruction & (1U << 25U)) != 0;
        const bool pre_index = (instruction & (1U << 24U)) != 0;
        const bool add = (instruction & (1U << 23U)) != 0;
        const bool byte_transfer = (instruction & (1U << 22U)) != 0;
        const bool writeback = (instruction & (1U << 21U)) != 0 || !pre_index;
        const bool load = (instruction & (1U << 20U)) != 0;
        const auto rn = (instruction >> 16U) & 0xfU;
        const auto rd = (instruction >> 12U) & 0xfU;
        const auto base = arm_register(state, rn, pc);
        std::uint32_t offset = instruction & 0xfffU;
        if (register_offset) {
            if ((instruction & (1U << 4U)) != 0) return fault("register-specified ARM load/store shift is unsupported");
            const auto rm = instruction & 0xfU;
            const auto shift_type = (instruction >> 5U) & 3U;
            const auto shift_amount = (instruction >> 7U) & 0x1fU;
            offset = shift_value(arm_register(state, rm, pc), shift_type, shift_amount,
                flag(state.cpsr, kCpsrC), true).value;
        }
        const auto adjusted = add ? base + offset : base - offset;
        const auto address = pre_index ? adjusted : base;
        if (rn == 15 && writeback) return fault("writeback using the ARM PC base is unpredictable");
        if (load) {
            std::uint32_t value = 0;
            if (!read_guest_value(memory, address, byte_transfer ? 1U : 4U, value)) {
                return fault("ARM LDR accessed unmapped or unreadable guest memory");
            }
            if (rd == 15) branch_exchange(state, value);
            else state.r[rd] = value;
        } else {
            const auto value = rd == 15 ? pc + 12U : state.r[rd];
            if (!write_guest_value(memory, address, byte_transfer ? 1U : 4U, value)) {
                return fault("ARM STR accessed unmapped or read-only guest memory");
            }
        }
        if (writeback) state.r[rn] = adjusted;
        return {};
    }

    if ((instruction & 0x0e000090U) == 0x00000090U) {
        const bool pre_index = (instruction & (1U << 24U)) != 0;
        const bool add_offset = (instruction & (1U << 23U)) != 0;
        const bool immediate_offset = (instruction & (1U << 22U)) != 0;
        const bool encoded_writeback = (instruction & (1U << 21U)) != 0;
        const bool writeback = encoded_writeback || !pre_index;
        const bool encoded_load = (instruction & (1U << 20U)) != 0;
        const auto rn = (instruction >> 16U) & 0xfU;
        const auto rd = (instruction >> 12U) & 0xfU;
        const auto operation = (instruction >> 5U) & 3U;
        if (!pre_index && encoded_writeback) return fault("A32 unprivileged halfword/doubleword transfer is unsupported");
        unsigned transfer_size = 2;
        bool signed_load = false;
        bool doubleword_transfer = false;
        if (operation == 0U) return fault("unsupported A32 swap transfer encoding");
        if (operation == 2U) {
            if (encoded_load) {
                transfer_size = 1;
                signed_load = true;
            } else {
                transfer_size = 8;
                doubleword_transfer = true;
            }
        } else if (operation == 3U) {
            if (encoded_load) {
                signed_load = true;
            } else {
                transfer_size = 8;
                doubleword_transfer = true;
            }
        }
        // In the extra-transfer encoding, operation 10 with L=0 is LDRD rather than a store.
        const bool load = encoded_load || (doubleword_transfer && operation == 2U);
        if (rn == 15U || rd == 15U || (doubleword_transfer && ((rd & 1U) != 0 || rd > 12U))) {
            return fault("A32 halfword/doubleword transfer uses an unsupported PC or register pair");
        }
        if (writeback && (rn == rd || (doubleword_transfer && rn == rd + 1U))) {
            return fault("A32 halfword/doubleword transfer writeback overlaps its base and destination registers");
        }
        if (!load && operation != 1U && !doubleword_transfer) {
            return fault("unsupported A32 signed store encoding");
        }

        std::uint32_t offset = 0;
        if (immediate_offset) {
            offset = ((instruction >> 4U) & 0xf0U) | (instruction & 0xfU);
        } else {
            if (((instruction >> 8U) & 0xfU) != 0) return fault("invalid A32 register-offset halfword transfer encoding");
            const auto rm = instruction & 0xfU;
            if (rm == 15U) return fault("A32 register-offset halfword transfer using PC is unpredictable");
            offset = state.r[rm];
        }

        const auto base = state.r[rn];
        std::uint64_t adjusted = base;
        if (add_offset) {
            adjusted += offset;
        } else {
            if (offset > base) return fault("A32 halfword transfer address wraps the guest address space");
            adjusted -= offset;
        }
        if (adjusted > std::numeric_limits<std::uint32_t>::max()) {
            return fault("A32 halfword transfer address wraps the guest address space");
        }
        const auto address = static_cast<std::uint32_t>(pre_index ? adjusted : base);
        const auto address_end = static_cast<std::uint64_t>(address) + transfer_size;
        if (address_end > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U) {
            return fault("A32 halfword transfer access wraps the guest address space");
        }
        if ((transfer_size == 2U && (address & 1U) != 0)
            || (doubleword_transfer && (address & 3U) != 0)) {
            return fault("A32 halfword/doubleword transfer address is not naturally aligned");
        }
        if (doubleword_transfer) {
            const auto permission = load ? GuestPermission::Read : GuestPermission::Write;
            if (!memory.is_accessible(GuestAddress32{address}, transfer_size, permission)) {
                return fault(load ? "A32 doubleword load accessed unreadable guest memory"
                                  : "A32 doubleword store accessed read-only guest memory");
            }
            const auto second_address = static_cast<std::uint32_t>(address + sizeof(std::uint32_t));
            if (load) {
                const auto low = memory.read_u32(GuestAddress32{address});
                const auto high = memory.read_u32(GuestAddress32{second_address});
                if (!low.has_value() || !high.has_value()) return fault("A32 doubleword load failed after range validation");
                state.r[rd] = *low;
                state.r[rd + 1U] = *high;
            } else if (!memory.write_u32(GuestAddress32{address}, state.r[rd])
                || !memory.write_u32(GuestAddress32{second_address}, state.r[rd + 1U])) {
                return fault("A32 doubleword store failed after range validation");
            }
        } else if (load) {
            std::uint32_t value = 0;
            if (!read_guest_value(memory, address, transfer_size, value, signed_load)) {
                return fault("A32 halfword/signed load accessed unreadable guest memory");
            }
            state.r[rd] = value;
        } else if (!write_guest_value(memory, address, transfer_size, state.r[rd])) {
            return fault("A32 halfword store accessed read-only guest memory");
        }
        if (writeback) state.r[rn] = static_cast<std::uint32_t>(adjusted);
        return {};
    }

    if ((instruction & 0x0c000000U) == 0x00000000U) {
        const bool immediate = (instruction & (1U << 25U)) != 0;
        const auto opcode = (instruction >> 21U) & 0xfU;
        const bool set_flags = (instruction & (1U << 20U)) != 0;
        const auto rn = (instruction >> 16U) & 0xfU;
        const auto rd = (instruction >> 12U) & 0xfU;
        const auto left = arm_register(state, rn, pc);
        std::uint32_t right = 0;
        bool shifter_carry = flag(state.cpsr, kCpsrC);
        if (immediate) {
            const auto imm8 = instruction & 0xffU;
            const auto rotate = ((instruction >> 8U) & 0xfU) * 2U;
            right = std::rotr(imm8, static_cast<int>(rotate));
            if (rotate != 0) shifter_carry = (right >> 31U) != 0;
        } else {
            if ((instruction & (1U << 4U)) != 0) return fault("register-specified ARM operand shift is unsupported");
            const auto rm = instruction & 0xfU;
            const auto shift_type = (instruction >> 5U) & 3U;
            const auto shift_amount = (instruction >> 7U) & 0x1fU;
            const auto shifted = shift_value(arm_register(state, rm, pc), shift_type, shift_amount,
                shifter_carry, true);
            right = shifted.value;
            shifter_carry = shifted.carry;
        }

        const auto old_nzcv = state.cpsr & kCpsrNzcv;
        std::uint32_t result = 0;
        bool writes_result = true;
        bool arithmetic_flags = false;
        switch (opcode) {
            case 0: result = left & right; break; // AND
            case 1: result = left ^ right; break; // EOR
            case 2: result = sub_flags(state.cpsr, left, right); arithmetic_flags = true; break; // SUB
            case 3: result = sub_flags(state.cpsr, right, left); arithmetic_flags = true; break; // RSB
            case 4: result = add_flags(state.cpsr, left, right); arithmetic_flags = true; break; // ADD
            case 5: result = add_flags(state.cpsr, left, right, flag(state.cpsr, kCpsrC)); arithmetic_flags = true; break;
            case 6: result = sub_flags(state.cpsr, left, right, !flag(state.cpsr, kCpsrC)); arithmetic_flags = true; break;
            case 7: result = sub_flags(state.cpsr, right, left, !flag(state.cpsr, kCpsrC)); arithmetic_flags = true; break;
            case 8: result = left & right; writes_result = false; set_nz(state.cpsr, result); break; // TST
            case 9: result = left ^ right; writes_result = false; set_nz(state.cpsr, result); break; // TEQ
            case 10: result = sub_flags(state.cpsr, left, right); writes_result = false; arithmetic_flags = true; break;
            case 11: result = add_flags(state.cpsr, left, right); writes_result = false; arithmetic_flags = true; break;
            case 12: result = left | right; break;
            case 13: result = right; break;
            case 14: result = left & ~right; break;
            case 15: result = ~right; break;
            default: return fault("invalid ARM data-processing opcode");
        }
        if (arithmetic_flags && writes_result && !set_flags) {
            state.cpsr = (state.cpsr & ~kCpsrNzcv) | old_nzcv;
        }
        if (writes_result) {
            if (rd == 15) {
                if (set_flags) return fault("data-processing exception return to PC is unsupported");
                state.r[15] = result & ~3U;
                state.thumb_it_state = 0;
            } else {
                state.r[rd] = result;
            }
        }
        if (set_flags && !arithmetic_flags) {
            set_nz(state.cpsr, result);
            set_flag(state.cpsr, kCpsrC, shifter_carry);
        }
        return {};
    }

    return fault("unsupported A32 instruction at guest address " + std::to_string(pc)
        + " (word " + std::to_string(instruction) + ")");
}

[[nodiscard]] StepResult execute_thumb16(
    GuestCpuState32& state,
    GuestMemory& memory,
    const GuestSvcHandler& svc_handler,
    std::uint32_t pc,
    std::uint16_t instruction) {
    const auto reverse_opcode = instruction & 0xffc0U;
    if (reverse_opcode == 0xba00U || reverse_opcode == 0xba40U
        || reverse_opcode == 0xba80U || reverse_opcode == 0xbac0U) {
        const auto rm = (instruction >> 3U) & 7U;
        const auto rd = instruction & 7U;
        const auto value = state.r[rm];
        std::uint32_t result = 0;
        if (reverse_opcode == 0xba00U) {
            result = ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U)
                | ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
        } else if (reverse_opcode == 0xba40U) {
            result = ((value & 0x00ff00ffU) << 8U) | ((value & 0xff00ff00U) >> 8U);
        } else if (reverse_opcode == 0xba80U) {
            for (unsigned bit = 0; bit < 32; ++bit) {
                result |= ((value >> bit) & 1U) << (31U - bit);
            }
        } else {
            const auto low_halfword = static_cast<std::uint16_t>(((value & 0xffU) << 8U)
                | ((value >> 8U) & 0xffU));
            result = static_cast<std::uint32_t>(std::bit_cast<std::int16_t>(low_halfword));
        }
        state.r[rd] = result;
        return {};
    }

    if ((instruction & 0xf500U) == 0xb100U) {
        const bool branch_if_nonzero = (instruction & 0x0800U) != 0;
        const auto rn = instruction & 7U;
        const auto immediate = (((instruction >> 9U) & 1U) << 6U)
            | (((instruction >> 3U) & 0x1fU) << 1U);
        const bool should_branch = (state.r[rn] != 0) == branch_if_nonzero;
        if (should_branch) {
            state.r[15] = pc + 4U + immediate;
            state.thumb_it_state = 0;
        }
        return {};
    }

    if ((instruction & 0xff00U) == 0xbf00U) {
        const auto mask = instruction & 0x000fU;
        if (mask == 0) return {};
        const auto condition = (instruction >> 4U) & 0xfU;
        if (condition >= 0xeU) return fault("invalid Thumb IT condition");
        state.thumb_it_state = static_cast<std::uint8_t>(instruction & 0xffU);
        return {};
    }

    if ((instruction & 0xe000U) == 0x0000U) {
        const auto operation = (instruction >> 11U) & 3U;
        const auto rd = instruction & 7U;
        const auto rs = (instruction >> 3U) & 7U;
        const auto immediate = (instruction >> 6U) & 0x1fU;
        if (operation == 3U) {
            const bool use_immediate = (instruction & (1U << 10U)) != 0;
            const bool subtract = (instruction & (1U << 9U)) != 0;
            const auto operand = use_immediate ? immediate : state.r[(instruction >> 6U) & 7U];
            const auto left = state.r[rs];
            state.r[rd] = subtract ? sub_flags(state.cpsr, left, operand) : add_flags(state.cpsr, left, operand);
            return {};
        }
        const auto shifted = shift_value(state.r[rs], operation, immediate,
            flag(state.cpsr, kCpsrC), true);
        state.r[rd] = shifted.value;
        set_nz(state.cpsr, shifted.value);
        set_flag(state.cpsr, kCpsrC, shifted.carry);
        return {};
    }

    if ((instruction & 0xe000U) == 0x2000U) {
        const auto operation = (instruction >> 11U) & 3U;
        const auto rd = (instruction >> 8U) & 7U;
        const auto immediate = instruction & 0xffU;
        switch (operation) {
            case 0:
                state.r[rd] = immediate;
                set_nz(state.cpsr, immediate);
                break;
            case 1:
                (void)sub_flags(state.cpsr, state.r[rd], immediate);
                break;
            case 2:
                state.r[rd] = add_flags(state.cpsr, state.r[rd], immediate);
                break;
            case 3:
                state.r[rd] = sub_flags(state.cpsr, state.r[rd], immediate);
                break;
            default: break;
        }
        return {};
    }

    if ((instruction & 0xfc00U) == 0x4000U) {
        const auto operation = (instruction >> 6U) & 0xfU;
        const auto rm = (instruction >> 3U) & 7U;
        const auto rd = instruction & 7U;
        const auto left = state.r[rd];
        const auto right = state.r[rm];
        std::uint32_t result = 0;
        bool write_result = true;
        switch (operation) {
            case 0: result = left & right; set_nz(state.cpsr, result); break;
            case 1: result = left ^ right; set_nz(state.cpsr, result); break;
            case 2: {
                const auto amount = right & 0xffU;
                const auto shifted = shift_value(left, 0, amount, flag(state.cpsr, kCpsrC), false);
                result = shifted.value;
                set_nz(state.cpsr, result);
                if (amount != 0) set_flag(state.cpsr, kCpsrC, shifted.carry);
                break;
            }
            case 3: {
                const auto amount = right & 0xffU;
                const auto shifted = shift_value(left, 1, amount, flag(state.cpsr, kCpsrC), false);
                result = shifted.value;
                set_nz(state.cpsr, result);
                if (amount != 0) set_flag(state.cpsr, kCpsrC, shifted.carry);
                break;
            }
            case 4: {
                const auto amount = right & 0xffU;
                const auto shifted = shift_value(left, 2, amount, flag(state.cpsr, kCpsrC), false);
                result = shifted.value;
                set_nz(state.cpsr, result);
                if (amount != 0) set_flag(state.cpsr, kCpsrC, shifted.carry);
                break;
            }
            case 5: result = add_flags(state.cpsr, left, right, flag(state.cpsr, kCpsrC)); break;
            case 6: result = sub_flags(state.cpsr, left, right, !flag(state.cpsr, kCpsrC)); break;
            case 7: {
                const auto amount = right & 0xffU;
                const auto shifted = shift_value(left, 3, amount, flag(state.cpsr, kCpsrC), false);
                result = shifted.value;
                set_nz(state.cpsr, result);
                if (amount != 0) set_flag(state.cpsr, kCpsrC, shifted.carry);
                break;
            }
            case 8: result = left & right; write_result = false; set_nz(state.cpsr, result); break;
            case 9: result = sub_flags(state.cpsr, 0, right); break;
            case 10: result = sub_flags(state.cpsr, left, right); write_result = false; break;
            case 11: result = add_flags(state.cpsr, left, right); write_result = false; break;
            case 12: result = left | right; set_nz(state.cpsr, result); break;
            case 13: result = left * right; set_nz(state.cpsr, result); break;
            case 14: result = left & ~right; set_nz(state.cpsr, result); break;
            case 15: result = ~right; set_nz(state.cpsr, result); break;
            default: return fault("invalid Thumb ALU operation");
        }
        if (write_result) state.r[rd] = result;
        return {};
    }

    if ((instruction & 0xfc00U) == 0x4400U) {
        const auto operation = (instruction >> 8U) & 3U;
        const auto rd = ((instruction >> 7U) & 1U) << 3U | (instruction & 7U);
        const auto rm = ((instruction >> 6U) & 1U) << 3U | ((instruction >> 3U) & 7U);
        const auto right = thumb_register(state, rm, pc);
        if (operation == 0) {
            const auto result = thumb_register(state, rd, pc) + right;
            if (rd == 15) state.r[15] = result & ~1U;
            else state.r[rd] = result;
        } else if (operation == 1) {
            (void)sub_flags(state.cpsr, thumb_register(state, rd, pc), right);
        } else if (operation == 2) {
            if (rd == 15) state.r[15] = right & ~1U;
            else state.r[rd] = right;
        } else {
            const bool link = (instruction & (1U << 7U)) != 0;
            if (link) state.r[14] = (pc + 2U) | 1U;
            branch_exchange(state, right);
        }
        return {};
    }

    if ((instruction & 0xf800U) == 0x4800U) {
        const auto rd = (instruction >> 8U) & 7U;
        const auto address = ((pc + 4U) & ~3U) + ((instruction & 0xffU) << 2U);
        std::uint32_t value = 0;
        if (!read_guest_value(memory, address, 4, value)) return fault("Thumb literal LDR accessed unreadable memory");
        state.r[rd] = value;
        return {};
    }

    if ((instruction & 0xf000U) == 0x5000U) {
        const auto operation = (instruction >> 9U) & 7U;
        const auto rm = (instruction >> 6U) & 7U;
        const auto rn = (instruction >> 3U) & 7U;
        const auto rd = instruction & 7U;
        const auto address = state.r[rn] + state.r[rm];
        const auto size = (operation == 1U || operation == 5U || operation == 7U) ? 2U
            : (operation == 2U || operation == 3U || operation == 6U) ? 1U : 4U;
        const bool load = operation == 3U || operation >= 4U;
        if (load) {
            std::uint32_t value = 0;
            const bool sign = operation == 3U || operation == 7U;
            if (!read_guest_value(memory, address, size, value, sign)) return fault("Thumb register-offset load accessed unreadable memory");
            state.r[rd] = value;
        } else if (!write_guest_value(memory, address, size, state.r[rd])) {
            return fault("Thumb register-offset store accessed read-only memory");
        }
        return {};
    }

    if ((instruction & 0xe000U) == 0x6000U) {
        const auto operation = (instruction >> 11U) & 3U;
        const auto immediate = (instruction >> 6U) & 0x1fU;
        const auto rn = (instruction >> 3U) & 7U;
        const auto rd = instruction & 7U;
        const bool byte_transfer = (operation & 2U) != 0;
        const bool load = (operation & 1U) != 0;
        const auto address = state.r[rn] + (immediate << (byte_transfer ? 0U : 2U));
        const auto size = byte_transfer ? 1U : 4U;
        if (load) {
            std::uint32_t value = 0;
            if (!read_guest_value(memory, address, size, value)) return fault("Thumb immediate load accessed unreadable memory");
            state.r[rd] = value;
        } else if (!write_guest_value(memory, address, size, state.r[rd])) {
            return fault("Thumb immediate store accessed read-only memory");
        }
        return {};
    }

    if ((instruction & 0xf000U) == 0x8000U) {
        const bool load = (instruction & (1U << 11U)) != 0;
        const auto immediate = ((instruction >> 6U) & 0x1fU) << 1U;
        const auto rn = (instruction >> 3U) & 7U;
        const auto rd = instruction & 7U;
        const auto address = state.r[rn] + immediate;
        if (load) {
            std::uint32_t value = 0;
            if (!read_guest_value(memory, address, 2, value)) return fault("Thumb halfword load accessed unreadable memory");
            state.r[rd] = value;
        } else if (!write_guest_value(memory, address, 2, state.r[rd])) {
            return fault("Thumb halfword store accessed read-only memory");
        }
        return {};
    }

    if ((instruction & 0xf000U) == 0x9000U) {
        const bool load = (instruction & (1U << 11U)) != 0;
        const auto rd = (instruction >> 8U) & 7U;
        const auto address = state.r[13] + ((instruction & 0xffU) << 2U);
        if (load) {
            std::uint32_t value = 0;
            if (!read_guest_value(memory, address, 4, value)) return fault("Thumb SP-relative load accessed unreadable memory");
            state.r[rd] = value;
        } else if (!write_guest_value(memory, address, 4, state.r[rd])) {
            return fault("Thumb SP-relative store accessed read-only memory");
        }
        return {};
    }

    if ((instruction & 0xf000U) == 0xa000U) {
        const auto rd = (instruction >> 8U) & 7U;
        const auto base = (instruction & (1U << 11U)) != 0 ? state.r[13] : ((pc + 4U) & ~3U);
        state.r[rd] = base + ((instruction & 0xffU) << 2U);
        return {};
    }

    if ((instruction & 0xff00U) == 0xb000U) {
        const auto offset = (instruction & 0x7fU) << 2U;
        state.r[13] = (instruction & (1U << 7U)) != 0 ? state.r[13] - offset : state.r[13] + offset;
        return {};
    }

    if ((instruction & 0xfe00U) == 0xb400U || (instruction & 0xfe00U) == 0xbc00U) {
        const bool pop = (instruction & 0x0800U) != 0;
        const bool extra_register = (instruction & (1U << 8U)) != 0;
        const auto register_list = instruction & 0xffU;
        const auto count = static_cast<unsigned>(std::popcount(register_list)) + (extra_register ? 1U : 0U);
        if (count == 0) return fault("empty Thumb PUSH/POP register list");
        auto address = pop ? state.r[13] : state.r[13] - count * 4U;
        if (!pop) {
            for (unsigned reg = 0; reg < 8; ++reg) {
                if ((register_list & (1U << reg)) == 0) continue;
                if (!memory.write_u32(GuestAddress32{address}, state.r[reg])) return fault("Thumb PUSH accessed read-only memory");
                address += 4U;
            }
            if (extra_register && !memory.write_u32(GuestAddress32{address}, state.r[14])) return fault("Thumb PUSH LR accessed read-only memory");
            state.r[13] -= count * 4U;
        } else {
            for (unsigned reg = 0; reg < 8; ++reg) {
                if ((register_list & (1U << reg)) == 0) continue;
                const auto value = memory.read_u32(GuestAddress32{address});
                if (!value.has_value()) return fault("Thumb POP accessed unreadable memory");
                state.r[reg] = *value;
                address += 4U;
            }
            if (extra_register) {
                const auto value = memory.read_u32(GuestAddress32{address});
                if (!value.has_value()) return fault("Thumb POP PC accessed unreadable memory");
                branch_exchange(state, *value);
                address += 4U;
            }
            state.r[13] += count * 4U;
        }
        return {};
    }

    if ((instruction & 0xf000U) == 0xc000U) {
        const bool load = (instruction & (1U << 11U)) != 0;
        const auto rn = (instruction >> 8U) & 7U;
        const auto register_list = instruction & 0xffU;
        if (register_list == 0) return fault("empty Thumb LDM/STM register list");
        auto address = state.r[rn];
        for (unsigned reg = 0; reg < 8; ++reg) {
            if ((register_list & (1U << reg)) == 0) continue;
            if (load) {
                const auto value = memory.read_u32(GuestAddress32{address});
                if (!value.has_value()) return fault("Thumb LDM accessed unreadable memory");
                state.r[reg] = *value;
            } else if (!memory.write_u32(GuestAddress32{address}, state.r[reg])) {
                return fault("Thumb STM accessed read-only memory");
            }
            address += 4U;
        }
        if (load) {
            if ((register_list & (1U << rn)) == 0) state.r[rn] = address;
        } else {
            state.r[rn] = address;
        }
        return {};
    }

    if ((instruction & 0xf000U) == 0xd000U) {
        const auto condition = (instruction >> 8U) & 0xfU;
        if (condition == 0xfU) return execute_svc(state, memory, svc_handler, instruction & 0xffU);
        if (condition == 0xeU) return fault("undefined Thumb conditional branch encoding");
        if (condition_passed(state.cpsr, condition)) {
            const auto displacement = sign_extend(instruction & 0xffU, 8U) * 2;
            state.r[15] = static_cast<std::uint32_t>(static_cast<std::int64_t>(pc + 4U) + displacement) & ~1U;
            state.thumb_it_state = 0;
        }
        return {};
    }

    if ((instruction & 0xf800U) == 0xe000U) {
        const auto displacement = sign_extend(instruction & 0x07ffU, 11U) * 2;
        state.r[15] = static_cast<std::uint32_t>(static_cast<std::int64_t>(pc + 4U) + displacement) & ~1U;
        state.thumb_it_state = 0;
        return {};
    }

    return fault("unsupported T16 instruction at guest address " + std::to_string(pc)
        + " (halfword " + std::to_string(instruction) + ")");
}

[[nodiscard]] bool is_t32_movw(
    std::uint16_t first,
    std::uint16_t second,
    bool movt) noexcept {
    const auto expected = movt ? 0xf2c0U : 0xf240U;
    return (first & 0xfbf0U) == expected && (second & 0x8000U) == 0;
}

[[nodiscard]] std::uint16_t decode_t32_mov_immediate(
    std::uint16_t first,
    std::uint16_t second) noexcept {
    const auto imm4 = first & 0x000fU;
    const auto i = (first >> 10U) & 1U;
    const auto imm3 = (second >> 12U) & 7U;
    const auto imm8 = second & 0x00ffU;
    return static_cast<std::uint16_t>((imm4 << 12U) | (i << 11U) | (imm3 << 8U) | imm8);
}

[[nodiscard]] StepResult execute_thumb32(
    GuestCpuState32& state,
    GuestMemory& memory,
    std::uint32_t pc,
    std::uint16_t first,
    std::uint16_t second) {
    const auto combined_instruction = (static_cast<std::uint32_t>(first) << 16U) | second;
    if (const auto vfp_result = execute_vfp_data(state, combined_instruction); vfp_result.has_value()) return *vfp_result;

    const auto table_branch_opcode = second & 0xfff0U;
    if ((first & 0xfff0U) == 0xe8d0U
        && (table_branch_opcode == 0xf000U || table_branch_opcode == 0xf010U)) {
        const bool halfword_table = table_branch_opcode == 0xf010U;
        const auto rn = first & 0xfU;
        const auto rm = second & 0xfU;
        if (rm == 15U) return fault("T32 TBB/TBH index register cannot be PC");
        const auto base = thumb_register(state, rn, pc);
        const auto scaled_index = static_cast<std::uint64_t>(state.r[rm]) << (halfword_table ? 1U : 0U);
        const auto table_address = static_cast<std::uint64_t>(base) + scaled_index;
        const auto entry_size = halfword_table ? 2U : 1U;
        const auto guest_address_end = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
        if (table_address > std::numeric_limits<std::uint32_t>::max()
            || table_address + entry_size > guest_address_end) {
            return fault("T32 TBB/TBH table address wraps the guest address space");
        }
        if (halfword_table && (table_address & 1U) != 0) return fault("T32 TBH table address is not halfword-aligned");
        std::uint32_t branch_offset = 0;
        if (halfword_table) {
            const auto entry = memory.read_u16(GuestAddress32{static_cast<std::uint32_t>(table_address)});
            if (!entry.has_value()) return fault("T32 TBH accessed unreadable guest memory");
            branch_offset = *entry;
        } else {
            const auto entry = memory.read_u8(GuestAddress32{static_cast<std::uint32_t>(table_address)});
            if (!entry.has_value()) return fault("T32 TBB accessed unreadable guest memory");
            branch_offset = *entry;
        }
        state.r[15] = static_cast<std::uint32_t>(pc + 4U + (branch_offset << 1U)) & ~1U;
        state.cpsr |= kCpsrThumb;
        state.thumb_it_state = 0;
        return {};
    }

    const auto add_sub_w_opcode = first & 0xfbe0U;
    if (add_sub_w_opcode == 0xf200U || add_sub_w_opcode == 0xf2a0U) {
        const auto rn = first & 0xfU;
        const auto rd = (second >> 8U) & 0xfU;
        if (rd == 15U || (second & 0x8000U) != 0) return fault("invalid T32 ADDW/SUBW destination or encoding");
        const auto immediate = (((first >> 10U) & 1U) << 11U)
            | (((second >> 12U) & 7U) << 8U) | (second & 0xffU);
        const auto base = thumb_register(state, rn, pc);
        state.r[rd] = add_sub_w_opcode == 0xf200U ? base + immediate : base - immediate;
        return {};
    }

    const auto division_prefix = first & 0xfff0U;
    if ((division_prefix == 0xfb90U || division_prefix == 0xfbb0U)
        && (second & 0xf0f0U) == 0xf0f0U) {
        const bool signed_division = division_prefix == 0xfb90U;
        const auto rn = first & 0xfU;
        const auto rd = (second >> 8U) & 0xfU;
        const auto rm = second & 0xfU;
        if (rn == 15U || rd == 15U || rm == 15U) return fault("T32 SDIV/UDIV using PC is unpredictable");
        const auto divisor = state.r[rm];
        const auto dividend = state.r[rn];
        std::uint32_t quotient = 0;
        // As in A32, deterministic zero is used for the architecturally
        // UNPREDICTABLE divide-by-zero case.
        if (divisor != 0) {
            if (signed_division) {
                const auto signed_dividend = std::bit_cast<std::int32_t>(dividend);
                const auto signed_divisor = std::bit_cast<std::int32_t>(divisor);
                if (signed_dividend == std::numeric_limits<std::int32_t>::min() && signed_divisor == -1) {
                    quotient = 0x80000000U;
                } else {
                    quotient = std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(signed_dividend / signed_divisor));
                }
            } else {
                quotient = dividend / divisor;
            }
        }
        state.r[rd] = quotient;
        return {};
    }

    const auto bitfield_opcode = first & 0xfff0U;
    if (bitfield_opcode == 0xf340U || bitfield_opcode == 0xf360U || bitfield_opcode == 0xf3c0U) {
        const auto rn = first & 0xfU;
        const auto rd = (second >> 8U) & 0xfU;
        const auto lsb = (((second >> 12U) & 7U) << 2U) | ((second >> 6U) & 3U);
        const auto encoded_width = second & 0x1fU;
        if (rd == 15U || (second & 0x0020U) != 0) return fault("invalid T32 bitfield destination or reserved encoding");
        if (bitfield_opcode == 0xf360U) {
            if (encoded_width < lsb) return fault("T32 BFI/BFC msb is below lsb");
            const auto width = encoded_width - lsb + 1U;
            const auto mask = width == 32U ? 0xffffffffU : ((1U << width) - 1U) << lsb;
            const auto source = rn == 15U ? 0U : state.r[rn];
            state.r[rd] = (state.r[rd] & ~mask) | ((source << lsb) & mask);
            return {};
        }
        if (rn == 15U) return fault("T32 UBFX/SBFX using PC is unpredictable");
        const auto width = encoded_width + 1U;
        if (lsb + width > 32U) return fault("T32 UBFX/SBFX field exceeds the register width");
        const auto mask = width == 32U ? 0xffffffffU : (1U << width) - 1U;
        const auto field = (state.r[rn] >> lsb) & mask;
        if (bitfield_opcode == 0xf340U && width < 32U && (field & (1U << (width - 1U))) != 0) {
            state.r[rd] = field | ~mask;
        } else {
            state.r[rd] = field;
        }
        return {};
    }

    if (is_t32_movw(first, second, false) || is_t32_movw(first, second, true)) {
        const bool movt = is_t32_movw(first, second, true);
        const auto rd = (second >> 8U) & 0xfU;
        if (rd == 15) return fault("Thumb MOVW/MOVT targeting PC is undefined");
        const auto immediate = static_cast<std::uint32_t>(decode_t32_mov_immediate(first, second));
        if (movt) state.r[rd] = (state.r[rd] & 0x0000ffffU) | (immediate << 16U);
        else state.r[rd] = (state.r[rd] & 0xffff0000U) | immediate;
        return {};
    }

    if ((first & 0xf800U) == 0xf000U && (second & 0xd000U) == 0x8000U) {
        const auto condition = (first >> 6U) & 0xfU;
        if (condition >= 0xeU) return fault("invalid T32 conditional branch condition");
        if (condition_passed(state.cpsr, condition)) {
            const auto s = static_cast<std::uint32_t>((first >> 10U) & 1U);
            const auto j1 = static_cast<std::uint32_t>((second >> 13U) & 1U);
            const auto j2 = static_cast<std::uint32_t>((second >> 11U) & 1U);
            const auto encoded = (s << 20U) | (j1 << 19U) | (j2 << 18U)
                | (static_cast<std::uint32_t>(first & 0x003fU) << 12U)
                | (static_cast<std::uint32_t>(second & 0x07ffU) << 1U);
            const auto displacement = sign_extend(encoded, 21U);
            state.r[15] = static_cast<std::uint32_t>(static_cast<std::int64_t>(pc + 4U) + displacement) & ~1U;
            state.thumb_it_state = 0;
        }
        return {};
    }

    if ((first & 0xf800U) == 0xf000U
        && (((second & 0xd000U) == 0x9000U) || ((second & 0xd000U) == 0xd000U))) {
        const auto s = static_cast<std::uint32_t>((first >> 10U) & 1U);
        const auto j1 = static_cast<std::uint32_t>((second >> 13U) & 1U);
        const auto j2 = static_cast<std::uint32_t>((second >> 11U) & 1U);
        const auto i1 = (~(j1 ^ s)) & 1U;
        const auto i2 = (~(j2 ^ s)) & 1U;
        const auto encoded = (s << 24U) | (i1 << 23U) | (i2 << 22U)
            | (static_cast<std::uint32_t>(first & 0x03ffU) << 12U)
            | (static_cast<std::uint32_t>(second & 0x07ffU) << 1U);
        const auto displacement = sign_extend(encoded, 25U);
        if ((second & 0xd000U) == 0xd000U) state.r[14] = (pc + 4U) | 1U;
        state.r[15] = static_cast<std::uint32_t>(static_cast<std::int64_t>(pc + 4U) + displacement) & ~1U;
        state.cpsr |= kCpsrThumb;
        state.thumb_it_state = 0;
        return {};
    }

    if ((first & 0xfe40U) == 0xe800U) {
        const bool pre_index = (first & 0x0100U) != 0;
        const bool increment = (first & 0x0080U) != 0;
        const bool user_registers = (first & 0x0040U) != 0;
        const bool writeback = (first & 0x0020U) != 0;
        const bool load = (first & 0x0010U) != 0;
        const auto base_register = first & 0x000fU;
        const auto register_list = second;
        const auto register_count = static_cast<std::uint64_t>(std::popcount(register_list));
        if (register_count == 0) return fault("empty T32 LDM/STM register list is unsupported");
        if (user_registers) return fault("T32 LDM/STM user-register or exception-return forms are unsupported");
        if (base_register == 15U) return fault("T32 LDM/STM using PC as the base is unsupported");
        if (!load && (register_list & (1U << 15U)) != 0) {
            return fault("T32 STM with PC in the register list is unpredictable");
        }
        if (writeback && (register_list & (1U << base_register)) != 0) {
            return fault("T32 LDM/STM writeback with the base register in the register list is unsupported");
        }
        const auto base = state.r[base_register];
        if ((base & 3U) != 0) return fault("T32 LDM/STM base address is not word-aligned");

        const auto transfer_bytes = register_count * 4U;
        const auto start = increment
            ? static_cast<std::uint64_t>(base) + (pre_index ? 4U : 0U)
            : static_cast<std::uint64_t>(base) - transfer_bytes + (pre_index ? 0U : 4U);
        const auto writeback_value = increment
            ? static_cast<std::uint64_t>(base) + transfer_bytes
            : static_cast<std::uint64_t>(base) - transfer_bytes;
        const auto address_space_end = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
        if (start > std::numeric_limits<std::uint32_t>::max() || start + transfer_bytes > address_space_end
            || (writeback && writeback_value > std::numeric_limits<std::uint32_t>::max())) {
            return fault("T32 LDM/STM address range wraps the 32-bit guest address space");
        }
        const auto access = load ? GuestPermission::Read : GuestPermission::Write;
        if (!memory.is_accessible(GuestAddress32{static_cast<std::uint32_t>(start)}, transfer_bytes, access)) {
            return fault(load ? "T32 LDM accessed unreadable guest memory" : "T32 STM accessed read-only guest memory");
        }

        std::array<std::uint32_t, 16> loaded_registers{};
        std::optional<std::uint32_t> loaded_pc;
        auto address = static_cast<std::uint32_t>(start);
        for (unsigned reg = 0; reg < 16; ++reg) {
            if ((register_list & (1U << reg)) == 0) continue;
            if (load) {
                const auto value = memory.read_u32(GuestAddress32{address});
                if (!value.has_value()) return fault("T32 LDM read failed after guest-range validation");
                if (reg == 15U) loaded_pc = *value;
                else loaded_registers[reg] = *value;
            } else if (!memory.write_u32(GuestAddress32{address}, state.r[reg])) {
                return fault("T32 STM write failed after guest-range validation");
            }
            address += 4U;
        }
        if (load) {
            for (unsigned reg = 0; reg < 15; ++reg) {
                if ((register_list & (1U << reg)) != 0) state.r[reg] = loaded_registers[reg];
            }
            if (writeback) state.r[base_register] = static_cast<std::uint32_t>(writeback_value);
            if (loaded_pc.has_value()) {
                branch_exchange(state, *loaded_pc);
                state.thumb_it_state = 0;
            }
        } else if (writeback) {
            state.r[base_register] = static_cast<std::uint32_t>(writeback_value);
        }
        return {};
    }

    const auto first_opcode = first & 0xfff0U;
    const auto rd = (second >> 12U) & 0xfU;
    const auto rn = first & 0xfU;

    if ((second & 0x0800U) != 0) {
        unsigned indexed_size = 4;
        bool indexed_load = false;
        bool indexed_signed = false;
        bool indexed_store = false;
        switch (first_opcode) {
            case 0xf850U: indexed_load = true; break;  // LDR (immediate, indexed)
            case 0xf840U: indexed_store = true; break; // STR (immediate, indexed)
            case 0xf810U: indexed_load = true; indexed_size = 1; break;
            case 0xf800U: indexed_store = true; indexed_size = 1; break;
            case 0xf830U: indexed_load = true; indexed_size = 2; break;
            case 0xf820U: indexed_store = true; indexed_size = 2; break;
            case 0xf910U: indexed_load = true; indexed_size = 1; indexed_signed = true; break;
            case 0xf930U: indexed_load = true; indexed_size = 2; indexed_signed = true; break;
            default: break;
        }
        if (indexed_load || indexed_store) {
            const bool pre_index = (second & 0x0400U) != 0;
            const bool add_offset = (second & 0x0200U) != 0;
            const bool writeback = (second & 0x0100U) != 0;
            const auto offset = second & 0x00ffU;
            if (!pre_index && !writeback) return fault("invalid T32 indexed load/store addressing mode");
            if (writeback && (rn == 15U || rn == rd)) {
                return fault("T32 indexed load/store writeback uses an unpredictable register");
            }
            const auto base = thumb_register(state, rn, pc);
            std::uint32_t adjusted = base;
            if (add_offset) {
                if (offset > std::numeric_limits<std::uint32_t>::max() - base) {
                    return fault("T32 indexed load/store address wraps the guest address space");
                }
                adjusted = base + offset;
            } else {
                if (offset > base) return fault("T32 indexed load/store address wraps the guest address space");
                adjusted = base - offset;
            }
            const auto address = pre_index ? adjusted : base;
            const auto address_end = static_cast<std::uint64_t>(address) + indexed_size;
            if (address_end > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U) {
                return fault("T32 indexed load/store access wraps the guest address space");
            }
            if (indexed_load) {
                std::uint32_t value = 0;
                if (!read_guest_value(memory, address, indexed_size, value, indexed_signed)) {
                    return fault("T32 indexed load accessed unreadable guest memory");
                }
                if (rd == 15U) branch_exchange(state, value);
                else state.r[rd] = value;
            } else if (rd == 15U || !write_guest_value(memory, address, indexed_size, state.r[rd])) {
                return fault("T32 indexed store has invalid register or accessed read-only memory");
            }
            if (writeback) state.r[rn] = adjusted;
            return {};
        }
    }

    if ((second & 0x0800U) == 0) {
        unsigned indexed_size = 4;
        bool indexed_load = false;
        bool indexed_signed = false;
        bool indexed_store = false;
        switch (first_opcode) {
            case 0xf850U: indexed_load = true; break;  // LDR (register)
            case 0xf840U: indexed_store = true; break; // STR (register)
            case 0xf810U: indexed_load = true; indexed_size = 1; break;
            case 0xf800U: indexed_store = true; indexed_size = 1; break;
            case 0xf830U: indexed_load = true; indexed_size = 2; break;
            case 0xf820U: indexed_store = true; indexed_size = 2; break;
            case 0xf910U: indexed_load = true; indexed_size = 1; indexed_signed = true; break;
            case 0xf930U: indexed_load = true; indexed_size = 2; indexed_signed = true; break;
            default: break;
        }
        if (indexed_load || indexed_store) {
            const auto rm = second & 0xfU;
            if ((second & 0x0fc0U) != 0 || rn == 15U || rm == 15U || (!indexed_load && rd == 15U)) {
                return fault("invalid T32 register-offset load/store encoding or register");
            }
            const auto shift = (second >> 4U) & 3U;
            const auto base = state.r[rn];
            const auto offset = static_cast<std::uint64_t>(state.r[rm]) << shift;
            const auto address = static_cast<std::uint64_t>(base) + offset;
            const auto address_end = address + indexed_size;
            const auto address_space_end = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1U;
            if (address > std::numeric_limits<std::uint32_t>::max() || address_end > address_space_end) {
                return fault("T32 register-offset load/store address wraps the guest address space");
            }
            if (indexed_load) {
                std::uint32_t value = 0;
                if (!read_guest_value(memory, static_cast<std::uint32_t>(address), indexed_size, value, indexed_signed)) {
                    return fault("T32 register-offset load accessed unreadable guest memory");
                }
                if (rd == 15U) branch_exchange(state, value);
                else state.r[rd] = value;
            } else if (!write_guest_value(memory, static_cast<std::uint32_t>(address), indexed_size, state.r[rd])) {
                return fault("T32 register-offset store accessed read-only guest memory");
            }
            return {};
        }
    }

    unsigned size = 4;
    bool load = false;
    bool signed_load = false;
    if (first_opcode == 0xf8d0U) { load = true; size = 4; }
    else if (first_opcode == 0xf8c0U) { load = false; size = 4; }
    else if (first_opcode == 0xf890U) { load = true; size = 1; }
    else if (first_opcode == 0xf880U) { load = false; size = 1; }
    else if (first_opcode == 0xf8b0U) { load = true; size = 2; }
    else if (first_opcode == 0xf8a0U) { load = false; size = 2; }
    else if (first_opcode == 0xf990U) { load = true; size = 1; signed_load = true; }
    else if (first_opcode == 0xf9b0U) { load = true; size = 2; signed_load = true; }
    else return fault("unsupported T32 instruction at guest address " + std::to_string(pc));

    const auto base = thumb_register(state, rn, pc);
    const auto address = base + (second & 0x0fffU);
    if (load) {
        std::uint32_t value = 0;
        if (!read_guest_value(memory, address, size, value, signed_load)) return fault("T32 load accessed unreadable guest memory");
        if (rd == 15) branch_exchange(state, value);
        else state.r[rd] = value;
    } else if (rd == 15 || !write_guest_value(memory, address, size, state.r[rd])) {
        return fault("T32 store has invalid register or accessed read-only guest memory");
    }
    return {};
}

[[nodiscard]] bool thumb32_prefix(std::uint16_t first) noexcept {
    const auto prefix = first & 0xf800U;
    return prefix == 0xe800U || prefix == 0xf000U || prefix == 0xf800U;
}

void advance_it_state(GuestCpuState32& state) noexcept {
    if ((state.thumb_it_state & 7U) == 0) state.thumb_it_state = 0;
    else state.thumb_it_state = static_cast<std::uint8_t>((state.thumb_it_state & 0xe0U)
        | ((state.thumb_it_state << 1U) & 0x1fU));
}

}  // namespace

bool GuestTrampolineRegistry::register_trampoline(
    std::string name,
    GuestAddress32 guest_address,
    GuestTrampolineFunction function,
    std::string* diagnostic) {
    const auto fail = [&](const char* message) {
        if (diagnostic != nullptr) *diagnostic = message;
        return false;
    };
    if (name.empty() || !function) return fail("trampoline name and callback are required");
    const auto address = guest_address.value();
    const auto normalized = address & ~1U;
    if (entries_by_address_.contains(normalized)) return fail("guest trampoline address is already registered");
    if (addresses_by_name_.contains(name)) return fail("guest trampoline symbol name is already registered");
    entries_by_address_.emplace(normalized, Entry{std::move(name), address, std::move(function)});
    addresses_by_name_.emplace(entries_by_address_.at(normalized).name, normalized);
    return true;
}

bool GuestTrampolineRegistry::unregister_trampoline(GuestAddress32 guest_address) noexcept {
    const auto normalized = guest_address.value() & ~1U;
    const auto found = entries_by_address_.find(normalized);
    if (found == entries_by_address_.end()) return false;
    addresses_by_name_.erase(found->second.name);
    entries_by_address_.erase(found);
    return true;
}

std::optional<std::uint32_t> GuestTrampolineRegistry::resolve_symbol(std::string_view name) const noexcept {
    const auto found = addresses_by_name_.find(name);
    if (found == addresses_by_name_.end()) return std::nullopt;
    const auto entry = entries_by_address_.find(found->second);
    if (entry == entries_by_address_.end()) return std::nullopt;
    return entry->second.guest_address;
}

Arm32Interpreter::Arm32Interpreter(
    GuestMemory& memory,
    GuestTrampolineRegistry& trampolines,
    GuestSvcHandler svc_handler)
    : memory_(memory), trampolines_(trampolines), svc_handler_(std::move(svc_handler)) {}

const char* Arm32Interpreter::backend_name() const noexcept {
    return "RetroBridge A32/T32 interpreter";
}

bool Arm32Interpreter::available() const noexcept {
    return true;
}

ExecutionResult Arm32Interpreter::run(
    GuestCpuState32& state,
    GuestAddress32 entry,
    std::uint64_t instruction_budget) {
    const auto raw_entry = entry.value();
    const bool thumb = (raw_entry & 1U) != 0;
    if (!thumb && (raw_entry & 3U) != 0) {
        return {ExecutionStatus::GuestFault, 0, "A32 entry point is not word-aligned"};
    }
    state.r[15] = raw_entry & ~1U;
    if (thumb) state.cpsr |= kCpsrThumb;
    else state.cpsr &= ~kCpsrThumb;
    state.thumb_it_state = 0;
    std::uint64_t executed = 0;

    while (executed < instruction_budget) {
        const auto pc = state.r[15];
        const bool is_thumb = flag(state.cpsr, kCpsrThumb);
        if (const auto trampoline = trampolines_.entries_by_address_.find(pc);
            trampoline != trampolines_.entries_by_address_.end()) {
            const auto function = trampoline->second.function;
            const auto name = trampoline->second.name;
            const auto result = function(state, memory_);
            ++executed;
            if (result.action == GuestHookAction::Stop) {
                return {ExecutionStatus::Completed, executed, result.diagnostic};
            }
            if (result.action == GuestHookAction::Fault) {
                return {ExecutionStatus::GuestFault, executed, result.diagnostic.empty()
                    ? "guest trampoline reported a fault: " + name : result.diagnostic};
            }
            branch_exchange(state, state.r[14]);
            continue;
        }

        if (is_thumb) {
            std::array<std::byte, 2> first_bytes{};
            if (!memory_.read(GuestAddress32{pc}, first_bytes, GuestPermission::Execute)) {
                return {ExecutionStatus::GuestFault, executed, "T16 fetch from unmapped or non-executable guest memory"};
            }
            const auto first = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(first_bytes[0])
                | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(first_bytes[1])) << 8U));
            const bool wide = thumb32_prefix(first);
            std::uint16_t second = 0;
            if (wide) {
                std::array<std::byte, 2> second_bytes{};
                if (!memory_.read(GuestAddress32{pc + 2U}, second_bytes, GuestPermission::Execute)) {
                    return {ExecutionStatus::GuestFault, executed, "T32 second halfword fetch is unmapped or non-executable"};
                }
                second = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(second_bytes[0])
                    | (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(second_bytes[1])) << 8U));
            }
            state.r[15] = pc + (wide ? 4U : 2U);
            bool execute = true;
            if (state.thumb_it_state != 0) {
                execute = condition_passed(state.cpsr, state.thumb_it_state >> 4U);
                advance_it_state(state);
            }
            const auto result = execute
                ? (wide ? execute_thumb32(state, memory_, pc, first, second)
                    : execute_thumb16(state, memory_, svc_handler_, pc, first))
                : StepResult{};
            ++executed;
            if (result.action == GuestHookAction::Stop) {
                return {ExecutionStatus::Completed, executed, result.diagnostic};
            }
            if (result.action == GuestHookAction::Fault) {
                return {ExecutionStatus::GuestFault, executed, result.diagnostic};
            }
        } else {
            std::array<std::byte, 4> bytes{};
            if (!memory_.read(GuestAddress32{pc}, bytes, GuestPermission::Execute)) {
                return {ExecutionStatus::GuestFault, executed, "A32 fetch from unmapped or non-executable guest memory"};
            }
            std::uint32_t instruction = 0;
            for (std::size_t index = 0; index < bytes.size(); ++index) {
                instruction |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[index])) << (index * 8U);
            }
            state.r[15] = pc + 4U;
            const auto result = execute_arm(state, memory_, svc_handler_, pc, instruction);
            ++executed;
            if (result.action == GuestHookAction::Stop) {
                return {ExecutionStatus::Completed, executed, result.diagnostic};
            }
            if (result.action == GuestHookAction::Fault) {
                return {ExecutionStatus::GuestFault, executed, result.diagnostic};
            }
        }
    }
    return {ExecutionStatus::BudgetExhausted, executed, "guest instruction budget exhausted"};
}

void Arm32Interpreter::invalidate(GuestRange32 guest_code) noexcept {
    (void)guest_code;
}

}  // namespace retrobridge::runtime
