/*
 * Copyright 2019 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <wasm.h>

#include "src/binary-reader.h"
#include "src/error.h"
#include "src/error-formatter.h"
#include "src/interp/binary-reader-interp.h"
#include "src/interp/interp.h"
#include "src/ir.h"
#include "src/stream.h"

using namespace wabt;
using namespace wabt::interp;

static Features s_features;
static Stream* s_trace_stream;
static Thread::Options s_thread_options;
static std::unique_ptr<FileStream> s_log_stream;
static std::unique_ptr<FileStream> s_stdout_stream;

struct wasm_valtype_t {
  wasm_valkind_t kind;
};

struct wasm_engine_t {
};

struct wasm_store_t {
  wasm_store_t(Environment* env, Executor* executor) : env(env), executor(executor) {
  }

  ~wasm_store_t() {
    printf("CAPI: ~store\n");
    delete executor;
  }

  Environment* env;
  Executor* executor;
};

struct WasmInstance {
  WasmInstance(wasm_store_t* store, DefinedModule* module)
    : store(store), module(module), host_info(nullptr), finalizer(nullptr) {}

  ~WasmInstance() {
    //printf("CAPI: ~instance\n");
    if (finalizer) {
      finalizer(host_info);
    }
    delete module;
  }
  wasm_store_t* store;
  DefinedModule* module;
  void* host_info;
  void (*finalizer)(void*);
};

struct wasm_instance_t {
  std::shared_ptr<WasmInstance> ptr;
};

struct wasm_frame_t {
  wasm_instance_t* instance;
  size_t offset;
  uint32_t func_index;
};

struct wasm_module_t {
  wasm_module_t(const wasm_byte_vec_t* in, ModuleMetadata* metadata) : metadata(metadata) {
    wasm_byte_vec_copy(&binary, in);
  }
  ~wasm_module_t() {
    printf("CAPI: ~module\n");
    wasm_byte_vec_delete(&binary);
    delete metadata;
  }
  wasm_byte_vec_t binary;
  ModuleMetadata* metadata;
};

struct wasm_functype_t {
  interp::FuncSignature sig;
};

struct wasm_ref_t {
  ExternalKind kind;
  Index index;
  bool Same(const wasm_ref_t& other) const {
    return kind == other.kind && index == other.index;
  }
};

struct wasm_extern_t {
  bool own;
  std::shared_ptr<WasmInstance> instance;
  wasm_ref_t ref;
  bool Same(const wasm_extern_t& other) const {
    return ref.Same(other.ref);
  }
};

struct wasm_func_t : wasm_extern_t {
  interp::Func* GetFunc() const {
    auto* env = instance.get()->store->env;
    return env->GetFunc(ref.index);
  }
};

struct wasm_global_t : wasm_extern_t {
  interp::Global* GetGlobal() const {
    auto* env = instance.get()->store->env;
    return env->GetGlobal(ref.index);
  }
};

struct wasm_table_t : wasm_extern_t {
  interp::Table* GetTable() const {
    auto* env = instance.get()->store->env;
    return env->GetTable(ref.index);
  }
};

struct wasm_memory_t : wasm_extern_t {
  interp::Memory* GetMemory() const {
    auto* env = instance.get()->store->env;
    return env->GetMemory(ref.index);
  }
};

struct wasm_trap_t {
  wasm_trap_t(const wasm_message_t* msg) {
    wasm_name_copy(&message, msg);
  }
  wasm_message_t message;
};

struct wasm_globaltype_t {
  Type type;
  bool mutable_;
};

struct wasm_tabletype_t {
  wasm_valtype_t* elemtype;
  wasm_limits_t limits;
};

struct wasm_memorytype_t {
  wasm_limits_t limits;
};

static Type to_wabt_type(wasm_valkind_t kind) {
  switch (kind) {
    case WASM_I32:
      return Type::I32;
    case WASM_I64:
      return Type::I64;
    case WASM_F32:
      return Type::F32;
    case WASM_F64:
      return Type::F64;
    case WASM_ANYREF:
      return Type::Anyref;
    case WASM_FUNCREF:
      return Type::Funcref;
  }
  assert(false);
}

static TypedValue to_wabt_value(const wasm_val_t& value) {
  TypedValue out(to_wabt_type(value.kind));
  switch (value.kind) {
    case WASM_I32:
      out.set_i32(value.of.i32);
      break;
    case WASM_I64:
      out.set_i64(value.of.i64);
      break;
    case WASM_F32:
      out.set_f32(value.of.f32);
      break;
    case WASM_F64:
      out.set_f64(value.of.f64);
      break;
    default:
      printf("CAPI: unexpected wasm type: %d\n", value.kind);
      assert(false);
  }
  return out;
}

static void to_wabt_values(TypedValues& wabt_values,
                           const wasm_val_t values[],
                           size_t count) {
  for (size_t i = 0; i < count; i++) {
    wabt_values.push_back(to_wabt_value(values[i]));
  }
}

// wasm_byte_vec

void wasm_byte_vec_new(wasm_byte_vec_t* out, size_t size, const char* s) {
  wasm_byte_vec_new_uninitialized(out, size);
  memcpy(out->data, s, size);
}

void wasm_byte_vec_new_uninitialized(wasm_byte_vec_t* out, size_t size) {
  out->data = new wasm_byte_t[size];
  out->size = size;
}

void wasm_byte_vec_copy(wasm_byte_vec_t* out, const wasm_byte_vec_t* vec) {
  wasm_byte_vec_new_uninitialized(out, vec->size);
  memcpy(out->data, vec->data, vec->size);
}

void wasm_byte_vec_delete(wasm_byte_vec_t* vec) {
  assert(vec);
  delete vec->data;
  vec->size = 0;
  vec->data = nullptr;
}

static wasm_val_t from_wabt_value(const TypedValue& value) {
  wasm_val_t out_value;
  switch (value.type) {
    case Type::I32:
      out_value.kind = WASM_I32;
      out_value.of.i32 = value.get_i32();
      break;
    case Type::I64:
      out_value.kind = WASM_I64;
      out_value.of.i64 = value.get_i64();
      break;
    case Type::F32:
      out_value.kind = WASM_F32;
      out_value.of.f32 = value.get_f32();
      break;
    case Type::F64:
      out_value.kind = WASM_F64;
      out_value.of.f64 = value.get_f64();
      break;
    default:
      printf("CAPI: unexpected wabt type: %d\n", value.type);
      assert(false);
  }
  return out_value;
}

static void from_wabt_values(wasm_val_t values[],
                             const TypedValues& wabt_values) {
  for (size_t i = 0; i < wabt_values.size(); i++) {
    values[i] = from_wabt_value(wabt_values[i]);
  }
}

extern "C" {

// wasm_valtype

wasm_valtype_t* wasm_valtype_new(wasm_valkind_t kind) {
  return new wasm_valtype_t{kind};
}

wasm_valkind_t wasm_valtype_kind(const wasm_valtype_t* type) {
  assert(type);
  return type->kind;
}

// wasm_valtype_vec

void wasm_valtype_vec_new_uninitialized(wasm_valtype_vec_t* vec, size_t size) {
  printf("ACPI: wasm_valtype_vec_new_uninitialized: %lu\n", size);
  vec->size = size;
  vec->data = new wasm_valtype_t*[size];
}

void wasm_valtype_vec_new(wasm_valtype_vec_t* vec,
                          size_t size,
                          wasm_valtype_t * const types[]) {
  wasm_valtype_vec_new_uninitialized(vec, size);
  memcpy(vec->data, types, size*sizeof(wasm_valtype_t *));
}

void wasm_valtype_vec_new_empty(wasm_valtype_vec_t* out) {
  out->data = nullptr;
  out->size = 0;
}

// Helpers

static void print_sig(const interp::FuncSignature& sig) {
  printf("(");
  bool first = true;
  for (auto Type : sig.param_types) {
    if (!first) {
      printf(", ");
    }
    first = false;
    printf("%s", GetTypeName(Type));
  }
  printf(") -> (");
  first = true;
  for (auto Type : sig.result_types) {
    if (!first) {
      printf(", ");
    }
    first = false;
    printf("%s", GetTypeName(Type));
  }
  printf(")");
}

// wasm_val

void wasm_val_copy(wasm_val_t* out, const wasm_val_t* in) {
  *out = *in;
}


// wasm_trap

wasm_trap_t* wasm_trap_new(wasm_store_t* store, const wasm_message_t* msg) {
  return new wasm_trap_t(msg);
}

void wasm_trap_message(const wasm_trap_t* trap, wasm_message_t* out) {
  assert(trap);
  wasm_name_copy(out, &trap->message);
}

wasm_frame_t* wasm_trap_origin(const wasm_trap_t* trap) {
  // TODO(sbc): Implement stack traces
  return nullptr;
}

void wasm_trap_trace(const wasm_trap_t* trap, wasm_frame_vec_t* out) {
  assert(trap);
  assert(out);
  wasm_frame_vec_new_empty(out);
  //std::string msg(trap->message.data, trap->message.size);
  //fprintf(stderr, "error: %s\n", msg.c_str());
  return;
}

void wasm_trap_delete(wasm_trap_t* trap) {
  assert(trap);
  delete trap;
  return;
}

// wasm_engine

wasm_engine_t* wasm_engine_new() {
  return new wasm_engine_t();
}

wasm_engine_t* wasm_engine_new_with_config(wasm_config_t*) {
  assert(false);
  return nullptr;
}

void wasm_engine_delete(wasm_engine_t* engine) {
  assert(engine);
  delete engine;
}

// wasm_store

wasm_store_t* wasm_store_new(wasm_engine_t* engine) {
  assert(engine);
  if (!s_trace_stream) {
    s_trace_stream = s_stdout_stream.get();
  }
  Environment* env = new Environment;;
  Executor* executor = new Executor(env, s_trace_stream, s_thread_options);
  return new wasm_store_t(env, executor);
}

void wasm_store_delete(wasm_store_t* store) {
  assert(store);
  delete store;
}

// wasm_module

static ReadBinaryOptions get_options() {
  const bool kReadDebugNames = true;
  const bool kStopOnFirstError = true;
  const bool kFailOnCustomSectionError = true;
  return ReadBinaryOptions(s_features, s_log_stream.get(), kReadDebugNames,
                           kStopOnFirstError, kFailOnCustomSectionError);
}

wasm_module_t* wasm_module_new(wasm_store_t*, const wasm_byte_vec_t* binary) {
  Errors errors;
  ModuleMetadata* metadata = nullptr;
  wabt::Result result = ReadBinaryMetadata(binary->data, binary->size,
                                           get_options(), &errors, &metadata);
  if (!Succeeded(result)) {
    return nullptr;
  }
  return new wasm_module_t(binary, metadata);
}

void wasm_module_delete(wasm_module_t* module) {
  assert(module);
  delete module;
}

// wasm_instance

wasm_instance_t* wasm_instance_new(wasm_store_t* store,
                                   const wasm_module_t* module,
                                   const wasm_extern_t* const imports[],
                                   wasm_trap_t** trap_out) {
  assert(module);
  assert(module->metadata);
  assert(store);
  assert(store->env);

  Errors errors;
  interp::DefinedModule* interp_module = nullptr;
  std::vector<interp::Export> wabt_imports;
  std::vector<interp::Export*> wabt_import_ptrs;

  for (size_t i = 0; i < module->metadata->imports.size(); i++) {
    wabt_imports.emplace_back("", imports[i]->ref.kind, imports[i]->ref.index);
  }

  for (auto& i: wabt_imports) {
    wabt_import_ptrs.push_back(&i);
  }

  wabt::Result result = ReadBinaryInterp(store->env, module->binary.data,
                                         module->binary.size, get_options(),
                                         wabt_import_ptrs, &errors,
                                         &interp_module);

  FormatErrorsToFile(errors, Location::Type::Binary);
  if (!Succeeded(result)) {
    printf("ReadBinaryInterp failed!\n");
    return nullptr;
  }

  ExecResult exec_result = store->executor->RunStartFunction(interp_module);
  if (exec_result.result != interp::Result::Ok) {
    printf("RunStartFunction failed!\n");
    wasm_name_t msg;
    wasm_name_new_from_string(&msg, ResultToString(exec_result.result));
    wasm_trap_t* trap = wasm_trap_new(store, &msg);
    *trap_out = trap;
    return nullptr;
  }
  return new wasm_instance_t{std::make_shared<WasmInstance>(store, interp_module)};
}

void wasm_instance_delete(wasm_instance_t* instance) {
  assert(instance);
  delete instance;
}

void wasm_instance_exports(const wasm_instance_t* instance,
                           wasm_extern_vec_t* out) {
  WasmInstance& wasm_instance = *instance->ptr.get();
  interp::DefinedModule* module = const_cast<interp::DefinedModule*>(wasm_instance.module);
  size_t num_exports = module->exports.size();
  wasm_extern_vec_new_uninitialized(out, num_exports);

  for (size_t i = 0; i < num_exports; i++) {
    interp::Export* export_ = &module->exports[i];
    printf("CAPI: getexport: '%s' %d\n", export_->name.c_str(), export_->kind);
    switch (export_->kind) {
      case ExternalKind::Func:
      case ExternalKind::Global:
      case ExternalKind::Memory:
      case ExternalKind::Table: {
        printf("CAPI: -> %p'\n", out->data[i]);
        out->data[i] = new wasm_extern_t{false, instance->ptr, {export_->kind, export_->index}};
        break;
      } default:
        assert(false);
    }
  }
}

void wasm_instance_set_host_info_with_finalizer(wasm_instance_t* instance,
                                                void* host_info,
                                                void (*finalizer)(void*)) {
  assert(instance);
  WasmInstance& wasm_instance = *instance->ptr.get();
  wasm_instance.host_info = host_info;
  wasm_instance.finalizer = finalizer;
}

// wasm_functype

wasm_functype_t* wasm_functype_new(wasm_valtype_vec_t* params, wasm_valtype_vec_t* results) {
  std::vector<Type> param_vec;
  std::vector<Type> result_vec;
  for (size_t i = 0; i < params->size; i++) {
    param_vec.push_back(to_wabt_type(wasm_valtype_kind(params->data[i])));
  }
  for (size_t i = 0; i < results->size; i++) {
    result_vec.push_back(to_wabt_type(wasm_valtype_kind(results->data[i])));
  }

  auto res = new wasm_functype_t{interp::FuncSignature{param_vec, result_vec}};
  printf("CAPI: wasm_functype_new ");

  print_sig(res->sig);
  printf("\n");
  return res;
}

void wasm_functype_delete(wasm_functype_t* functype) {
  printf("CAPI: wasm_functype_delete\n");
  assert(functype);
  delete(functype);
}

// wasm_func

static wasm_func_t* do_wasm_func_new(wasm_store_t* store,
                                     const wasm_functype_t* type,
                                     wasm_func_callback_t host_callback,
                                     wasm_func_callback_with_env_t host_callback_with_env,
                                     void* env,
                                     void (*finalizer)(void*)) {
  HostFunc::Callback callback = [host_callback, host_callback_with_env, env](
                                 const HostFunc* func,
                                 const interp::FuncSignature* sig,
                                 const TypedValues& args,
                                 TypedValues& results) -> interp::Result {
    printf("CAPI: calling host function: ");
    print_sig(*sig);
    printf("\n");
    wasm_val_t* host_args = new wasm_val_t[args.size()];
    wasm_val_t* host_results = new wasm_val_t[sig->result_types.size()];
    from_wabt_values(host_args, args);
    wasm_trap_t* trap;
    if (host_callback) {
      trap = host_callback(host_args, host_results);
    } else {
      assert(host_callback_with_env);
      trap = host_callback_with_env(env, host_args, host_results);
    }
    if (trap) {
      printf("CAPI: host function trapped\n");
      assert(false);
    }
    for (size_t i = 0; i < sig->result_types.size(); i++) {
      results[i] = to_wabt_value(host_results[i]);
      printf("adding result value: %s\n", TypedValueToString(results.back()).c_str());
    }
    return interp::Result::Ok;
  };

  static int function_count = 0;
  std::string name = std::string("function") + std::to_string(function_count++);
  store->env->EmplaceBackFuncSignature(type->sig);
  Index sig_index = store->env->GetFuncSignatureCount() - 1;
  auto* host_func = new HostFunc("extern", name, sig_index, callback);
  store->env->EmplaceBackFunc(host_func);
  Index func_index = store->env->GetFuncCount() - 1;
  auto instance = std::make_shared<WasmInstance>(store, nullptr);
  return wasm_extern_as_func(new wasm_extern_t{true, instance, {ExternalKind::Func, func_index}});
}

wasm_func_t* wasm_func_new(wasm_store_t* store,
                           const wasm_functype_t* type,
                           wasm_func_callback_t callback) {
  return do_wasm_func_new(store, type, callback, nullptr, nullptr, nullptr);

}

wasm_func_t* wasm_func_new_with_env(wasm_store_t* store,
                                    const wasm_functype_t* type,
                                    wasm_func_callback_with_env_t callback,
                                    void* env,
                                    void (*finalizer)(void*)) {
  return do_wasm_func_new(store, type, nullptr, callback, env, finalizer);
}

wasm_functype_t* wasm_func_type(const wasm_func_t* func) {
  assert(func);
  auto* env = func->instance.get()->store->env;
  interp::Func* wabt_func = func->GetFunc();
  return new wasm_functype_t{*env->GetFuncSignature(wabt_func->sig_index)};
}

void wasm_func_delete(wasm_func_t* func) {
  assert(func);
  delete func;
}

wasm_trap_t* wasm_func_call(const wasm_func_t* f,
                            const wasm_val_t args[],
                            wasm_val_t results[]) {

  printf("CAPI: wasm_func_call\n");
  assert(f);
  wasm_store_t* store = f->instance.get()->store;
  assert(store);
  Executor* exec = store->executor;
  wasm_functype_t* functype = wasm_func_type(f);
  TypedValues wabt_args;
  to_wabt_values(wabt_args, args, functype->sig.param_types.size());
  wasm_functype_delete(functype);
  assert(f->ref.kind == ExternalKind::Func);
  ExecResult res = exec->RunFunction(f->ref.index, wabt_args);
  if (res.result != interp::Result::Ok) {
    const char* msg = ResultToString(res.result);
    printf("CAPI: wasm_func_call failed: %s\n", msg);
    wasm_name_t message;
    wasm_name_new_from_string(&message, msg);
    wasm_trap_t* trap = wasm_trap_new(store, &message);
    wasm_name_delete(&message);
    return trap;
  }
  from_wabt_values(results, res.values);
  return nullptr;
}

wasm_ref_t* wasm_func_as_ref(wasm_func_t* function) {
  return wasm_extern_as_ref(wasm_func_as_extern(function));
}

// wasm_extern_vec

void wasm_extern_vec_new(wasm_extern_vec_t* vec, size_t size, wasm_extern_t * const[]) {
  assert(false);
}

void wasm_extern_vec_new_uninitialized(wasm_extern_vec_t* vec, size_t size) {
  printf("CAPI: wasm_extern_vec_new_uninitialized: %lu\n", size);
  vec->size = size;
  vec->data = new wasm_extern_t*[size];
}

void wasm_extern_vec_delete(wasm_extern_vec_t* vec) {
  assert(vec && vec->data);
  delete(vec->data);
  vec->size = 0;
}

// wasm_globaltype

wasm_globaltype_t* wasm_global_type(const wasm_global_t* global) {
  assert(global);
  assert(false);
}

// wasm_tabletype

wasm_tabletype_t* wasm_tabletype_new(wasm_valtype_t* type, const wasm_limits_t* limits) {
  return new wasm_tabletype_t{type, *limits};
}

const wasm_valtype_t* wasm_tabletype_element(const wasm_tabletype_t* type) {
  return type->elemtype;
}

const wasm_limits_t* wasm_tabletype_limits(const wasm_tabletype_t* type){
  return &type->limits;
}

void wasm_tabletype_delete(wasm_tabletype_t* t) {
  assert(t);
  delete t;
}

// wasm_memorytype

wasm_memorytype_t* wasm_memorytype_new(const wasm_limits_t* limits) {
  return new wasm_memorytype_t{*limits};
}

void wasm_memorytype_delete(wasm_memorytype_t* t) {
  assert(t);
  delete t;
}

// wasm_global

wasm_globaltype_t* wasm_globaltype_new(wasm_valtype_t* type,
                                       wasm_mutability_t mut) {
  assert(type);
  return new wasm_globaltype_t{to_wabt_type(type->kind), mut == WASM_VAR};
}

void wasm_globaltype_delete(wasm_globaltype_t* type) {
  assert(type);
  delete type;
}

wasm_global_t* wasm_global_new(wasm_store_t* store,
                               const wasm_globaltype_t* type,
                               const wasm_val_t* val) {
  assert(store && store && type);
  TypedValue value = to_wabt_value(*val);
  printf("CAPI: wasm_global_new: %s\n", TypedValueToString(value).c_str());
  store->env->EmplaceBackGlobal(value, type->mutable_);
  Index global_index = store->env->GetGlobalCount() - 1;
  auto instance = std::make_shared<WasmInstance>(store, nullptr);
  return wasm_extern_as_global(new wasm_extern_t{true, instance, {ExternalKind::Global, global_index}});
}

void wasm_global_delete(wasm_global_t* global) {
  assert(global);
  delete global;
}

wasm_global_t* wasm_global_copy(const wasm_global_t* in) {
  assert(in);
  return new wasm_global_t(*in);
}

bool wasm_global_same(const wasm_global_t* a, const wasm_global_t* b) {
  return wasm_extern_same(wasm_global_as_extern_const(a), wasm_global_as_extern_const(b));
}

void wasm_global_get(const wasm_global_t* global, wasm_val_t* out) {
  assert(global);
  printf("CAPI: wasm_global_get");
  interp::Global* interp_global = global->GetGlobal();
  printf(" -> %s\n", TypedValueToString(interp_global->typed_value).c_str());
  *out = from_wabt_value(interp_global->typed_value);
  return;
}

void wasm_global_set(wasm_global_t* global, const wasm_val_t* val) {
  printf("CAPI: wasm_global_set\n");
  interp::Global* g = global->GetGlobal();
  g->typed_value = to_wabt_value(*val);
}

// wasm_table

wasm_table_t* wasm_table_new(wasm_store_t* store, const wasm_tabletype_t* type,
                             wasm_ref_t* init) {
  store->env->EmplaceBackTable(to_wabt_type(type->elemtype->kind),
                               Limits(type->limits.min, type->limits.max));
  Index index = store->env->GetTableCount() - 1;
  auto instance = std::make_shared<WasmInstance>(store, nullptr);
  return wasm_extern_as_table(new wasm_extern_t{true, instance, {ExternalKind::Table, index}});
}

wasm_table_t* wasm_table_copy(const wasm_table_t* table) {
  return wasm_extern_as_table(new wasm_extern_t(*wasm_table_as_extern_const(table)));
}

void wasm_table_delete(wasm_table_t* table) {
  assert(table);
  delete table;
}

bool wasm_table_same(const wasm_table_t* a, const wasm_table_t* b) {
  assert(a && b);
  return a->Same(*b);
}

wasm_tabletype_t* wasm_table_type(const wasm_table_t*) {
  assert(false);
  return nullptr;
}

wasm_table_size_t wasm_table_size(const wasm_table_t* table) {
  return table->GetTable()->func_indexes.size();
}

wasm_ref_t* wasm_table_get(const wasm_table_t* t, wasm_table_size_t index) {
  interp::Table* table = t->GetTable();
  // TODO(sbc): This duplicates code from the CallIndirect handler.  I imagine
  // we will refactor this when we implment the TableGet opcode.
  if (index >= table->func_indexes.size())
    return nullptr;
  Index func_index = table->func_indexes[index];
  if (func_index == kInvalidIndex)
    return nullptr;
  printf("CAPI: wasm_table_get: %u -> %u\n", index, func_index);
  return new wasm_ref_t{ExternalKind::Func, func_index};
}

bool wasm_table_set(wasm_table_t* t, wasm_table_size_t index, wasm_ref_t* ref) {
  interp::Table* table = t->GetTable();
  if (ref && ref->kind != ExternalKind::Func) {
    return false;
  }
  if (index >= table->func_indexes.size()) {
    return false;
  }
  table->func_indexes[index] = ref ? ref->index : kInvalidIndex;
  return true;
}

bool wasm_table_grow(wasm_table_t* t, wasm_table_size_t delta,
                     wasm_ref_t* init) {
  interp::Table* table = t->GetTable();
  size_t cursize = table->func_indexes.size();
  size_t newsize = cursize + delta;
  if (newsize > table->limits.max) {
    return false;
  }
  printf("CAPI: wasm_table_grow %lu -> %lu\n", cursize, newsize);
  if (init && init->kind != ExternalKind::Func) {
    return false;
  }
  Index init_index = kInvalidIndex;
  if (init) {
    init_index = init->index;
  }
  table->func_indexes.resize(newsize, init_index);
  return true;
}

// wams_memory

wasm_memory_t* wasm_memory_new(wasm_store_t* store, const wasm_memorytype_t* type) {
  store->env->EmplaceBackMemory(Limits(type->limits.min, type->limits.max));
  Index index = store->env->GetMemoryCount() - 1;
  auto instance = std::make_shared<WasmInstance>(store, nullptr);
  return wasm_extern_as_memory(new wasm_extern_t{true, instance, {ExternalKind::Memory, index}});
}

void wasm_memory_delete(wasm_memory_t* memory) {
  assert(memory);
  delete memory;
}

bool wasm_memory_same(const wasm_memory_t* a, const wasm_memory_t* b) {
  assert(a && b);
  return a->Same(*b);
}

wasm_memory_t* wasm_memory_copy(const wasm_memory_t* memory) {
  return wasm_extern_as_memory(new wasm_extern_t(*wasm_memory_as_extern_const(memory)));
}

byte_t* wasm_memory_data(wasm_memory_t* m) {
  interp::Memory* memory = m->GetMemory();
  return memory->data.data();
}

wasm_memory_pages_t wasm_memory_size(const wasm_memory_t* m) {
  interp::Memory* memory = m->GetMemory();
  return memory->data.size() / WABT_PAGE_SIZE;
}

size_t wasm_memory_data_size(const wasm_memory_t* m) {
  interp::Memory* memory = m->GetMemory();
  return memory->data.size();
}

bool wasm_memory_grow(wasm_memory_t* m, wasm_memory_pages_t delta) {
  interp::Memory* memory = m->GetMemory();
  size_t cursize = memory->data.size() / WABT_PAGE_SIZE;
  size_t newsize = cursize + delta;
  if (newsize > memory->page_limits.max) {
    return false;
  }
  printf("CAPI: wasm_memory_grow %lu -> %lu\n", cursize, newsize);
  memory->data.resize(newsize * WABT_PAGE_SIZE);
  return true;
}

// wasm_frame

wasm_instance_t* wasm_frame_instance(const wasm_frame_t* frame) {
  assert(frame);
  return frame->instance;
}

size_t wasm_frame_module_offset(const wasm_frame_t* frame) {
  assert(frame);
  return frame->offset;
}

size_t wasm_frame_func_offset(const wasm_frame_t* frame) {
  assert(false);
  return 0;
}

uint32_t wasm_frame_func_index(const wasm_frame_t* frame) {
  assert(frame);
  return frame->func_index;
}

void wasm_frame_delete(wasm_frame_t* frame) {
  assert(frame);
  delete frame;
}

// wasm_frame_vec

void wasm_frame_vec_new_empty(wasm_frame_vec_t* out) {
  out->data = nullptr;
  out->size = 0;
}

void wasm_frame_vec_delete(wasm_frame_vec_t* vec) {
  assert(vec);
  if (vec->data) {
    delete(vec->data);
  }
  vec->size = 0;
}

// wams_ref

void wasm_ref_delete(wasm_ref_t* ref) {
  assert(ref);
  delete ref;
}

// Externals
wasm_extern_t* wasm_func_as_extern(wasm_func_t* func) {
  return static_cast<wasm_extern_t*>(func);
}

wasm_func_t* wasm_extern_as_func(wasm_extern_t* ext) {
  return static_cast<wasm_func_t*>(ext);
}

wasm_extern_t* wasm_table_as_extern(wasm_table_t* table) {
  return static_cast<wasm_extern_t*>(table);
}

wasm_table_t* wasm_extern_as_table(wasm_extern_t* ext) {
  return static_cast<wasm_table_t*>(ext);
}

wasm_extern_t* wasm_global_as_extern(wasm_global_t* global) {
  return static_cast<wasm_extern_t*>(global);
}

const wasm_extern_t* wasm_table_as_extern_const(const wasm_table_t* table) {
  return static_cast<const wasm_extern_t*>(table);
}

const wasm_extern_t* wasm_global_as_extern_const(const wasm_global_t* global) {
  return static_cast<const wasm_extern_t*>(global);
}

wasm_global_t* wasm_extern_as_global(wasm_extern_t* ext) {
  return static_cast<wasm_global_t*>(ext);
}

wasm_extern_t* wasm_memory_as_extern(wasm_memory_t* memory) {
  return static_cast<wasm_extern_t*>(memory);
}

const wasm_extern_t* wasm_memory_as_extern_const(const wasm_memory_t* memory) {
  return static_cast<const wasm_extern_t*>(memory);
}

wasm_memory_t* wasm_extern_as_memory(wasm_extern_t* ext) {
  return static_cast<wasm_memory_t*>(ext);
}

wasm_ref_t* wasm_extern_as_ref(wasm_extern_t* ext) {
  assert(ext);
  return &ext->ref;
}

bool wasm_extern_same(const wasm_extern_t* a, const wasm_extern_t* b) {
  return a->Same(*b);
}

}
