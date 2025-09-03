import {
  createOnMessage as __wasmCreateOnMessageForFsProxy,
  getDefaultContext as __emnapiGetDefaultContext,
  instantiateNapiModuleSync as __emnapiInstantiateNapiModuleSync,
  WASI as __WASI,
} from '@napi-rs/wasm-runtime'



const __wasi = new __WASI({
  version: 'preview1',
})

const __wasmUrl = new URL('./davey.wasm32-wasi.wasm', import.meta.url).href
const __emnapiContext = __emnapiGetDefaultContext()


const __sharedMemory = new WebAssembly.Memory({
  initial: 4000,
  maximum: 65536,
  shared: true,
})

const __wasmFile = await fetch(__wasmUrl).then((res) => res.arrayBuffer())

const {
  instance: __napiInstance,
  module: __wasiModule,
  napiModule: __napiModule,
} = __emnapiInstantiateNapiModuleSync(__wasmFile, {
  context: __emnapiContext,
  asyncWorkPoolSize: 4,
  wasi: __wasi,
  onCreateWorker() {
    const worker = new Worker(new URL('./wasi-worker-browser.mjs', import.meta.url), {
      type: 'module',
    })

    return worker
  },
  overwriteImports(importObject) {
    importObject.env = {
      ...importObject.env,
      ...importObject.napi,
      ...importObject.emnapi,
      memory: __sharedMemory,
    }
    return importObject
  },
  beforeInit({ instance }) {
    for (const name of Object.keys(instance.exports)) {
      if (name.startsWith('__napi_register__')) {
        instance.exports[name]()
      }
    }
  },
})
export default __napiModule.exports
export const Codec = __napiModule.exports.Codec
export const DAVE_PROTOCOL_VERSION = __napiModule.exports.DAVE_PROTOCOL_VERSION
export const MediaType = __napiModule.exports.MediaType
export const ProposalsOperationType = __napiModule.exports.ProposalsOperationType
export const SessionStatus = __napiModule.exports.SessionStatus
export const DAVESession = __napiModule.exports.DAVESession
export const DaveSession = __napiModule.exports.DaveSession
export const DEBUG_BUILD = __napiModule.exports.DEBUG_BUILD
export const generateDisplayableCode = __napiModule.exports.generateDisplayableCode
export const generateKeyFingerprint = __napiModule.exports.generateKeyFingerprint
export const generateP256Keypair = __napiModule.exports.generateP256Keypair
export const generatePairwiseFingerprint = __napiModule.exports.generatePairwiseFingerprint
export const VERSION = __napiModule.exports.VERSION
