// abstraction of Digital Signature Algorithm implementation
export interface ISigner {
  id?: string
  sign(signable: { data: Uint8Array }): Promise<Uint8Array>
}
