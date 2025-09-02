#include <fstream>
#include <iostream>
#include <string>

#include "include/v8.h"
#include "include/libplatform/libplatform.h"

using namespace v8;

static Isolate* isolate = nullptr;

// Compatibility with v8 versions that have different ScriptOrigin constructors
template <typename... Args>
ScriptOrigin CreateScriptOrigin(Args&&... args) {
  if constexpr (std::is_constructible_v<ScriptOrigin, Isolate*, Local<String>>) {
      return ScriptOrigin(isolate, std::forward<Args>(args)...);
  } else {
      return ScriptOrigin(std::forward<Args>(args)...);
  }
}

static void loadBytecode(uint8_t* bytecodeBuffer, int length) {
  // Load code into code cache.
  ScriptCompiler::CachedData* cached_data =
      new ScriptCompiler::CachedData(bytecodeBuffer, length);

  // Create dummy source.
  ScriptOrigin origin = CreateScriptOrigin(String::NewFromUtf8Literal(isolate, "code.jsc"));

  ScriptCompiler::Source source(String::NewFromUtf8Literal(isolate, "\"ಠ_ಠ\""),
                                origin, cached_data);

  // Compile code from code cache to print disassembly.
  MaybeLocal<UnboundScript> script = ScriptCompiler::CompileUnboundScript(
      isolate, &source, ScriptCompiler::kConsumeCodeCache);
}

static void readAllBytes(const std::string& file, std::vector<char>& buffer) {
  std::ifstream infile(file, std::ios::binary);

  infile.seekg(0, infile.end);
  size_t length = infile.tellg();
  infile.seekg(0, infile.beg);

  if (length > 0) {
    buffer.resize(length);
    infile.read(&buffer[0], length);
  }
}

int main(int argc, char* argv[]) {
  V8::SetFlagsFromString("--no-lazy --no-flush-bytecode");

  V8::InitializeICU();
  std::unique_ptr<Platform> platform = platform::NewDefaultPlatform();
  V8::InitializePlatform(platform.get());
  V8::Initialize();

  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      ArrayBuffer::Allocator::NewDefaultAllocator();

  isolate = Isolate::New(create_params);
  Isolate::Scope isolate_scope(isolate);
  HandleScope handle_scope(isolate);
  Local<v8::Context> context = Context::New(isolate);
  Context::Scope context_scope(context);

  std::vector<char> data;
  readAllBytes(argv[1], data);
  loadBytecode((uint8_t*)data.data(), data.size());
}
