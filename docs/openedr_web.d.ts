declare namespace wasm_bindgen {
    /* tslint:disable */
    /* eslint-disable */

}
declare type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

declare interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly web_add_unwhitelisted_subdomain: (a: number, b: number) => number;
    readonly web_alloc: (a: number) => number;
    readonly web_apk_loaded: () => number;
    readonly web_free: (a: number, b: number) => void;
    readonly web_free_str: (a: number) => void;
    readonly web_inspect_url: (a: number, b: number, c: number) => number;
    readonly web_inspect_url_content: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly web_is_unwhitelisted_subdomain: (a: number, b: number) => number;
    readonly web_load_benign_whitelist: (a: number, b: number) => number;
    readonly web_load_model: (a: number, b: number, c: number) => number;
    readonly web_load_url_rules: (a: number, b: number) => number;
    readonly web_load_url_whitelist: (a: number, b: number) => number;
    readonly web_load_yara: (a: number, b: number) => number;
    readonly web_load_yara_rules: (a: number, b: number) => number;
    readonly web_load_yara_src: (a: number, b: number) => number;
    readonly web_output_len: () => number;
    readonly web_scan_bytes: (a: number, b: number, c: number, d: number) => number;
    readonly web_scan_bytes_ex: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: bigint, h: bigint) => number;
    readonly web_scan_url: (a: number, b: number) => number;
    readonly web_self_test: () => number;
    readonly web_set_registry_rules: (a: number, b: number) => number;
    readonly web_set_string_rules: (a: number, b: number) => number;
    readonly wasm_bindgen_25783ceea4f8f12a___convert__closures_____invoke___wasm_bindgen_25783ceea4f8f12a___JsValue__wasm_bindgen_25783ceea4f8f12a___JsValue__wasm_bindgen_25783ceea4f8f12a___JsValue__wasm_bindgen_25783ceea4f8f12a___JsValue__wasm_bindgen_25783ceea4f8f12a___JsValue__true_: (a: number, b: number, c: any, d: any, e: any, f: any) => any;
    readonly __wbindgen_malloc_command_export: (a: number, b: number) => number;
    readonly __wbindgen_realloc_command_export: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store_command_export: (a: number) => void;
    readonly __externref_table_alloc_command_export: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure_command_export: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
declare function wasm_bindgen (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
