cd wasm-micro-runtime 
git checkout main
git pull
cd ..

rm -r build
mkdir -p build
cd build
cmake ../wasm-micro-runtime/product-mini/platforms/linux-sgx
make
