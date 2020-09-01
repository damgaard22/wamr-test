cd wasm-micro-runtime
git checkout cfcaca3
cd ..

mkdir -p build
cd build
cmake ../wasm-micro-runtime/product-mini/platforms/linux-sgx
make
