from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout, CMakeDeps
from conan.tools.files import get, copy, collect_libs
from conan.errors import ConanInvalidConfiguration
import os

required_conan_version = ">=2.0"

class AhoiSerialLibConan(ConanFile):
    name = "ahoi-serial-lib"
    version = "1.0.0"
    description = "Ahoi serial communication library with optional Ascon AEAD security"
    url = "https://github.com/dmochkas/ahoi-serial-lib"
    # license = "UNKNOWN"
    # homepage = url
    topics = ("ahoi", "ascon", "security", "embedded", "serial communication")

    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "secure_mode": [True, False],
        "enable_tests": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "secure_mode": True,
        "enable_tests": False,
    }

    exports_sources = (
        "CMakeLists.txt",
        "config.cmake",
        "cmake/*",
        "src/*",
        "include/*",
        "tests/*",  # exported so tests can optionally run when enable_tests=True
    )

    ascon_lib_name = "ascon-c"
    ascon_lib_version = "1.3.0"

    @property
    def ascon_lib(self):
        return f"{self.ascon_lib_name}/{self.ascon_lib_version}@dochkas/experimental"

    cmocka_lib_name = "cmocka"
    cmocka_lib_version = "1.1.8"

    @property
    def cmocka_lib(self):
        return f"{self.cmocka_lib_name}/{self.cmocka_lib_version}"

    def layout(self):
        cmake_layout(self)

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def requirements(self):
        self.requires(self.ascon_lib, options={"shared": self.options.shared})

        if self.options.enable_tests:
            self.requires(self.cmocka_lib)


    def configure(self):
        # if self.options.shared:  # Library CMake only defines STATIC
            # raise ConanInvalidConfiguration("Only static build supported by upstream CMake")
        if self.options.get_safe("fPIC") is False and self.options.shared:
            raise ConanInvalidConfiguration("fPIC disabled for shared build (unsupported)")

    def validate(self):
        if self.settings.os != "Linux":
            raise ConanInvalidConfiguration(f"This recipe supports only Linux. Detected os={self.settings.os}")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()

        tc = CMakeToolchain(self)
        # Pass algorithm / implementation selections
        tc.variables["CMAKE_POLICY_VERSION_MINIMUM"] = 3.5
        # Feature toggles
        tc.cache_variables["SECURE_MODE"] = "ON" if self.options.secure_mode else "OFF"
        tc.cache_variables["ENABLE_TESTS"] = "ON" if self.options.enable_tests else "OFF"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if self.options.enable_tests:
            cmake.test()

    def package(self):
        zlog_license = os.path.join(self.build_folder, "_deps", "zlog-src", "LICENSE")
        if os.path.isfile(zlog_license):
            copy(self, "LICENSE", dst="licenses", src=os.path.dirname(zlog_license), keep_path=False)

        # Public headers
        copy(self, "*.h", dst=os.path.join(self.package_folder, "include"), src=os.path.join(self.source_folder, "include", "pub"))

        # Libraries
        for pattern in ("*.a", "*.lib", "*.so", "*.dylib", "*.dll"):
            copy(self, pattern, dst=os.path.join(self.package_folder, "lib"), src=self.build_folder, keep_path=False)
    def package_info(self):
        self.cpp_info.libs = collect_libs(self)
        # Consumer compile definitions reflecting build configuration
        if self.options.secure_mode:
            self.cpp_info.defines.append("SECURE_MODE")