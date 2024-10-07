import * as chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
import 'mocha';
import { verifyWithLabel } from '../src/util';
const expect = chai.expect;

describe('verifyWithLabel', () => {
  it('should verify leafnodes properly', () => {
    const data = new Uint8Array([
      0x40, 0x41, 0x04, 0x00, 0x36, 0xBB, 0x23, 0x5C, 0xEC, 0x1B, 0x08, 0xE9, 0x1E, 0x61, 0x50, 0x37, 
      0x0E, 0xA4, 0x6B, 0x85, 0xD4, 0x14, 0x52, 0x2D, 0xFC, 0xD6, 0xCC, 0x8F, 0x67, 0x66, 0x53, 0x5C, 
      0xCE, 0x32, 0x34, 0x28, 0x82, 0x1E, 0x51, 0x3D, 0xE7, 0x66, 0xEB, 0xFB, 0x17, 0x8C, 0xC2, 0x01, 
      0x38, 0x64, 0x9F, 0x37, 0x17, 0xE8, 0x57, 0x03, 0xDE, 0xE1, 0xEA, 0x97, 0x53, 0x53, 0x27, 0x17, 
      0x26, 0x26, 0xFB, 0x40, 0x41, 0x04, 0xE6, 0xE8, 0x6A, 0x4B, 0xFE, 0xB0, 0x72, 0x5D, 0x2D, 0x22, 
      0xF5, 0x1D, 0x72, 0xA1, 0x7F, 0xDA, 0xDA, 0xB2, 0xB5, 0x61, 0xA6, 0xE1, 0x20, 0x12, 0x5F, 0xED, 
      0xDC, 0x0B, 0xF3, 0x7E, 0xCF, 0xB9, 0x7B, 0x86, 0x95, 0x80, 0xC8, 0xC0, 0xEB, 0x4E, 0xFF, 0x46, 
      0x3B, 0xFE, 0x43, 0x3C, 0xF9, 0x95, 0xD4, 0x72, 0x14, 0xE7, 0x49, 0x79, 0x99, 0x43, 0x1B, 0x7E, 
      0x44, 0xA4, 0x14, 0x58, 0xF3, 0xD6, 0x00, 0x01, 0x08, 0x02, 0x31, 0x81, 0x07, 0x09, 0x00, 0x00, 
      0x00, 0x02, 0x00, 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 
    ]);
  
    const signature = new Uint8Array([
      0x30, 0x44, 0x02, 0x20, 0x7C, 0x52, 0xF3, 0xF5, 0x66, 0x51, 0x81, 0x0C, 0x48, 0x4D, 0xA3, 0x3A, 
      0x1C, 0xBF, 0x8B, 0x9B, 0x9A, 0x38, 0xC3, 0x2E, 0x25, 0x38, 0xD4, 0x3C, 0x97, 0xAF, 0xEB, 0xAD, 
      0x1E, 0x45, 0xFE, 0xDD, 0x02, 0x20, 0x25, 0x82, 0x4F, 0xA6, 0x90, 0xC3, 0xDE, 0x49, 0x3F, 0xDC, 
      0x74, 0xF7, 0x4F, 0x94, 0x6E, 0xB3, 0x2F, 0x51, 0x67, 0xB2, 0x5B, 0xC6, 0xAF, 0xCD, 0xCC, 0xB6, 
      0xA1, 0xD5, 0x7E, 0x82, 0x83, 0xC6, 
    ]);
  
    const key = new Uint8Array([
      0x04, 0xE6, 0xE8, 0x6A, 0x4B, 0xFE, 0xB0, 0x72, 0x5D, 0x2D, 0x22, 0xF5, 0x1D, 0x72, 0xA1, 0x7F, 
      0xDA, 0xDA, 0xB2, 0xB5, 0x61, 0xA6, 0xE1, 0x20, 0x12, 0x5F, 0xED, 0xDC, 0x0B, 0xF3, 0x7E, 0xCF, 
      0xB9, 0x7B, 0x86, 0x95, 0x80, 0xC8, 0xC0, 0xEB, 0x4E, 0xFF, 0x46, 0x3B, 0xFE, 0x43, 0x3C, 0xF9, 
      0x95, 0xD4, 0x72, 0x14, 0xE7, 0x49, 0x79, 0x99, 0x43, 0x1B, 0x7E, 0x44, 0xA4, 0x14, 0x58, 0xF3, 
      0xD6, 
    ]);
  
    expect(verifyWithLabel(key, 'LeafNodeTBS', signature, data)).to.eventually.equal(true);
  });

  it('should verify keypackages properly', () => {
    const data = new Uint8Array([
      0x00, 0x01, 0x00, 0x02, 0x40, 0x41, 0x04, 0x5E, 0x02, 0xF4, 0xFC, 0xCD, 0x03, 0xA8, 0x7E, 0x26, 
      0xD8, 0xE0, 0x3B, 0x69, 0xBF, 0xF1, 0x73, 0xEF, 0x93, 0xEA, 0x90, 0xB0, 0x5E, 0x47, 0x0E, 0xA9, 
      0x5E, 0x9E, 0x35, 0x74, 0xC4, 0xAB, 0x5D, 0x57, 0x78, 0xB3, 0xFC, 0x93, 0x76, 0xDB, 0x42, 0xC4, 
      0xEE, 0x33, 0xDB, 0x47, 0xD2, 0x3F, 0x90, 0x4C, 0x29, 0xF4, 0x50, 0x0D, 0x6C, 0x3B, 0x67, 0x83, 
      0xDF, 0xE2, 0x9C, 0x8F, 0xBF, 0xAE, 0xB3, 0x40, 0x41, 0x04, 0x00, 0x36, 0xBB, 0x23, 0x5C, 0xEC, 
      0x1B, 0x08, 0xE9, 0x1E, 0x61, 0x50, 0x37, 0x0E, 0xA4, 0x6B, 0x85, 0xD4, 0x14, 0x52, 0x2D, 0xFC, 
      0xD6, 0xCC, 0x8F, 0x67, 0x66, 0x53, 0x5C, 0xCE, 0x32, 0x34, 0x28, 0x82, 0x1E, 0x51, 0x3D, 0xE7, 
      0x66, 0xEB, 0xFB, 0x17, 0x8C, 0xC2, 0x01, 0x38, 0x64, 0x9F, 0x37, 0x17, 0xE8, 0x57, 0x03, 0xDE, 
      0xE1, 0xEA, 0x97, 0x53, 0x53, 0x27, 0x17, 0x26, 0x26, 0xFB, 0x40, 0x41, 0x04, 0xE6, 0xE8, 0x6A, 
      0x4B, 0xFE, 0xB0, 0x72, 0x5D, 0x2D, 0x22, 0xF5, 0x1D, 0x72, 0xA1, 0x7F, 0xDA, 0xDA, 0xB2, 0xB5, 
      0x61, 0xA6, 0xE1, 0x20, 0x12, 0x5F, 0xED, 0xDC, 0x0B, 0xF3, 0x7E, 0xCF, 0xB9, 0x7B, 0x86, 0x95, 
      0x80, 0xC8, 0xC0, 0xEB, 0x4E, 0xFF, 0x46, 0x3B, 0xFE, 0x43, 0x3C, 0xF9, 0x95, 0xD4, 0x72, 0x14, 
      0xE7, 0x49, 0x79, 0x99, 0x43, 0x1B, 0x7E, 0x44, 0xA4, 0x14, 0x58, 0xF3, 0xD6, 0x00, 0x01, 0x08, 
      0x02, 0x31, 0x81, 0x07, 0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 
      0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
      0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x40, 0x46, 0x30, 0x44, 0x02, 0x20, 0x7C, 0x52, 0xF3, 0xF5, 0x66, 
      0x51, 0x81, 0x0C, 0x48, 0x4D, 0xA3, 0x3A, 0x1C, 0xBF, 0x8B, 0x9B, 0x9A, 0x38, 0xC3, 0x2E, 0x25, 
      0x38, 0xD4, 0x3C, 0x97, 0xAF, 0xEB, 0xAD, 0x1E, 0x45, 0xFE, 0xDD, 0x02, 0x20, 0x25, 0x82, 0x4F, 
      0xA6, 0x90, 0xC3, 0xDE, 0x49, 0x3F, 0xDC, 0x74, 0xF7, 0x4F, 0x94, 0x6E, 0xB3, 0x2F, 0x51, 0x67, 
      0xB2, 0x5B, 0xC6, 0xAF, 0xCD, 0xCC, 0xB6, 0xA1, 0xD5, 0x7E, 0x82, 0x83, 0xC6, 0x00, 
    ]);
  
    const signature = new Uint8Array([
      0x30, 0x45, 0x02, 0x20, 0x5D, 0x1C, 0x99, 0x92, 0x0A, 0x68, 0xCB, 0x5D, 0xAF, 0x51, 0xD9, 0xE4, 
      0xAA, 0x9B, 0x8E, 0x22, 0x23, 0x9C, 0xFB, 0x95, 0x64, 0x01, 0x58, 0x0F, 0x2C, 0x33, 0x04, 0xED, 
      0xD8, 0x14, 0xC9, 0x76, 0x02, 0x21, 0x00, 0x9A, 0x4A, 0xB6, 0x95, 0x2E, 0xA8, 0xCF, 0x72, 0x0D, 
      0xB2, 0x54, 0xC5, 0x40, 0x8E, 0xE2, 0x8E, 0x2B, 0xE5, 0x54, 0xEF, 0x4E, 0xCE, 0x81, 0xA8, 0x7F, 
      0x0E, 0x96, 0x62, 0x9F, 0x90, 0x4C, 0xCB, 
    ]);
  
    const key = new Uint8Array([
      0x04, 0xE6, 0xE8, 0x6A, 0x4B, 0xFE, 0xB0, 0x72, 0x5D, 0x2D, 0x22, 0xF5, 0x1D, 0x72, 0xA1, 0x7F, 
      0xDA, 0xDA, 0xB2, 0xB5, 0x61, 0xA6, 0xE1, 0x20, 0x12, 0x5F, 0xED, 0xDC, 0x0B, 0xF3, 0x7E, 0xCF, 
      0xB9, 0x7B, 0x86, 0x95, 0x80, 0xC8, 0xC0, 0xEB, 0x4E, 0xFF, 0x46, 0x3B, 0xFE, 0x43, 0x3C, 0xF9, 
      0x95, 0xD4, 0x72, 0x14, 0xE7, 0x49, 0x79, 0x99, 0x43, 0x1B, 0x7E, 0x44, 0xA4, 0x14, 0x58, 0xF3, 
      0xD6, 
    ]);
  
    expect(verifyWithLabel(key, 'KeyPackageTBS', signature, data)).to.eventually.equal(true);
  });
});