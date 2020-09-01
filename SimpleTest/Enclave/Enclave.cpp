/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "Enclave_t.h"
#include "wasm_export.h"
#include "bh_platform.h"

static char global_heap_buf[100 * 1024 * 1024] = { 0 };

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "%s", string);
}


extern "C" {
    typedef void (*os_print_function_t)(const char* message);
    extern void os_set_print_function(os_print_function_t pf);

    void
    enclave_print(const char *message)
    {
        ocall_print(message);
    }
}


void
ecall_iwasm_main()
{
    uint32_t stack_size = 16 * 1024, heap_size = 16 * 1024;
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    wasm_exec_env_t exec_env;
    wasm_function_inst_t wasm_func_execute;
    RuntimeInitArgs init_args;
    char error_buf[128];
    const char *exception;
    char *wasm_file_buf;
    size_t wasm_file_size;

    os_set_print_function(enclave_print);

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        ocall_print("Init runtime environment failed.");
        ocall_print("\n");
        return;
    }

    ocall_read_file("biolib-tensor.wasm", (unsigned char **) &wasm_file_buf, (size_t * ) & wasm_file_size);

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load((uint8_t *) wasm_file_buf, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        ocall_print(error_buf);
        ocall_print("\n");
    }

    /* instantiate the module */
    if (!(wasm_module_inst = wasm_runtime_instantiate(wasm_module,
                                                      stack_size,
                                                      heap_size,
                                                      error_buf,
                                                      sizeof(error_buf)))) {
        ocall_print(error_buf);
        ocall_print("\n");
    }

    if (!(exec_env = wasm_runtime_create_exec_env(wasm_module_inst, stack_size))) {
        ocall_print("Could not create exec_env");
    }

    wasm_func_execute = wasm_runtime_lookup_function(wasm_module_inst, "execute_onnx", NULL);

    char *code;
    size_t code_size;
    char *data;
    size_t data_size;

    ocall_read_file("onnx_test.code", (unsigned char **) &code, (size_t * ) & code_size);
    ocall_read_file("onnx_test.data", (unsigned char **) &data, (size_t * ) & data_size);

    int32_t runtime_allocated_code;
    int32_t runtime_allocated_data;

    runtime_allocated_code = wasm_runtime_module_dup_data(wasm_module_inst, code, code_size);
    runtime_allocated_data = wasm_runtime_module_dup_data(wasm_module_inst, data, data_size);

    uint32_t argv[5];
    argv[0] = 8; 
    argv[1] = runtime_allocated_code;    // pass the buffer offset for the ONNX Model in WASM space.
    argv[2] = code_size;
    argv[3] = runtime_allocated_data;  // pass the buffer offset for the input data in WASM space.
    argv[4] = data_size;
    
    wasm_runtime_call_wasm(exec_env, wasm_func_execute, 5, argv);

    if ((exception = wasm_runtime_get_exception(wasm_module_inst))) {
        ocall_print(exception);
        ocall_print("\n");
    }

    uint32_t wasm_return_pointer = argv[0];

    uint32_t wasm_result_pointer_address = wasm_return_pointer;
    uint32_t wasm_length_address = wasm_return_pointer + 4;

    uint32_t length = *(uint32_t *) wasm_runtime_addr_app_to_native(wasm_module_inst,
                                                                    wasm_length_address);
    uint32_t result_pointer = *(uint32_t *) wasm_runtime_addr_app_to_native(wasm_module_inst,
                                                                            wasm_result_pointer_address);
    uint8_t *result = (uint8_t *) wasm_runtime_addr_app_to_native(wasm_module_inst, result_pointer);

    ocall_print((char *) result);


    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail2:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail1:
    /* destroy runtime environment */
    wasm_runtime_destroy();
}
