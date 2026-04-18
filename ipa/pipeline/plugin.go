package pipeline

// Plugin signing follows the same flow as framework signing.
// Each .appex plugin has its own Info.plist, executable, and CodeResources.
// The signComponent function in resign.go handles both frameworks and plugins.
//
// Future enhancement: support multiple provisioning profiles for extensions.
