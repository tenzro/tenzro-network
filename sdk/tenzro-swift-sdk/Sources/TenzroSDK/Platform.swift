// Foundation networking lives in a separate module on Linux. This lets the
// package build on Linux CI hosts as well as Apple platforms.
#if canImport(FoundationNetworking)
@_exported import FoundationNetworking
#endif
@_exported import Foundation
