### `CMakeLists.txt`
```cmake
cmake_minimum_required(VERSION 3.12)
project(Aegis_Protocol LANGUAGES CXX)

# Set C++ Standard to 17 (required for std::optional, std::variant, and filesystem)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# 1. Find Dependencies
# ---------------------------------------------------------------------------

# OpenSSL is critical for HMAC-SHA256 and X25519 operations
find_package(OpenSSL REQUIRED)

# Threads are required for the mutex-protected Vault and KeyStore
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# 2. Project Configuration
# ---------------------------------------------------------------------------

# Since the project is header-only, we include the current directory 
# so headers can resolve internal dependencies (e.g., #include "passport.h")
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# 3. Executables
# ---------------------------------------------------------------------------

# Add the end-to-end integration test
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/e2e-example.cpp")
    add_executable(uml001_e2e_test e2e-example.cpp)

    # Link against OpenSSL and System Threads
    target_link_libraries(uml001_e2e_test
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
    )

    # Apply optimization flags similar to the manual build command
    target_compile_options(uml001_e2e_test PRIVATE -O2 -Wall -Wextra)
    
    message(STATUS "Created target: uml001_e2e_test")
else()
    message(WARNING "e2e-example.cpp not found; skipping executable creation.")
endif()

# ---------------------------------------------------------------------------
# 4. Installation (Optional)
# ---------------------------------------------------------------------------

# Install headers for use in other projects
file(GLOB UML_HEADERS "*.h" "*.hpp")
install(FILES ${UML_HEADERS} DESTINATION include/uml001)

```

### How to build the project

1. **Create a build directory:**
```bash
mkdir build && cd build

```


2. **Generate the build files:**
```bash
cmake ..

```


3. **Compile the example:**
```bash
cmake --build .

```


4. **Run the integration test:**
```bash
./uml001_e2e_test

```



### Dependency Notes

* **OpenSSL:** Ensure you have the development headers installed (e.g., `libssl-dev` on Ubuntu/Debian or `openssl-devel` on RHEL/CentOS).
* **Compiler:** This project utilizes C++17 features like `std::optional` and `std::shared_ptr` with custom deleters; ensure you are using `g++ 7+` or `clang 5+`.
* **Crypto Utils:** Ensure that the internal `crypto_utils.h` file (referenced by your headers) is present in the same directory as the other headers.