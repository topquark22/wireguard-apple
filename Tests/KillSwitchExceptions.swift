// SPDX-License-Identifier: MIT

import Foundation
import NetworkExtension

@main
struct KillSwitchExceptionsTests {
    static func main() throws {
        let privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        let input = """
        [Interface]
        PrivateKey = \(privateKey)
        KillSwitchExceptions = 10.1.1.7/24, 192.168.2.1
        KillSwitchExceptions = fd12:3456::1/32
        """
        let config = try TunnelConfiguration(fromWgQuickConfig: input, called: "test")
        precondition(config.interface.killSwitchExceptions.map { $0.stringRepresentation } ==
            ["10.1.1.7/24", "192.168.2.1/32", "fd12:3456::1/32"])
        let roundTrip = try TunnelConfiguration(fromWgQuickConfig: config.asWgQuickConfig(), called: "test")
        precondition(config == roundTrip)

        for invalid in ["bogus", "10.0.0.1/33", "fd00::/129", "1.2.3.4/-1", "1.2.3.4,", "1.2.3.4,,::1", ""] {
            do {
                _ = try TunnelConfiguration(fromWgQuickConfig: "[Interface]\nPrivateKey = \(privateKey)\nKillSwitchExceptions = \(invalid)\n")
                preconditionFailure("Accepted invalid exception: \(invalid)")
            } catch TunnelConfiguration.ParseError.interfaceHasInvalidAddress {
                continue
            }
        }

        let settings = PacketTunnelSettingsGenerator(tunnelConfiguration: config, resolvedEndpoints: []).generateNetworkSettings()
        let v4Routes = settings.ipv4Settings?.excludedRoutes ?? []
        let v6Routes = settings.ipv6Settings?.excludedRoutes ?? []
        precondition(v4Routes.count == 2 && v6Routes.count == 1)
        precondition(v4Routes[0].destinationAddress == "10.1.1.0" && v4Routes[0].destinationSubnetMask == "255.255.255.0")
        precondition(v4Routes[1].destinationAddress == "192.168.2.1" && v4Routes[1].destinationSubnetMask == "255.255.255.255")
        precondition(v6Routes[0].destinationAddress == "fd12:3456::" && v6Routes[0].destinationNetworkPrefixLength.intValue == 32)

        let runtime = try TunnelConfiguration(fromUapiConfig: "private_key=\(config.interface.privateKey.hexKey)\n", basedOn: config)
        precondition(runtime.interface.killSwitchExceptions == config.interface.killSwitchExceptions)

        let model = TunnelViewModel(tunnelConfiguration: config)
        model.interfaceData[.listenPort] = "1234"
        guard case .saved(let edited) = model.save() else { preconditionFailure("Could not save edited config") }
        precondition(edited.interface.killSwitchExceptions == config.interface.killSwitchExceptions)
        model.interfaceData[.killSwitchExceptions] = "10.0.0.1/33"
        guard case .error = model.save() else { preconditionFailure("Editor accepted an invalid exception") }
        model.interfaceData[.killSwitchExceptions] = ""
        guard case .saved(let cleared) = model.save() else { preconditionFailure("Could not clear exceptions") }
        precondition(cleared.interface.killSwitchExceptions.isEmpty)
        let emptySettings = PacketTunnelSettingsGenerator(tunnelConfiguration: cleared, resolvedEndpoints: []).generateNetworkSettings()
        precondition((emptySettings.ipv4Settings?.excludedRoutes ?? []).isEmpty)
        precondition((emptySettings.ipv6Settings?.excludedRoutes ?? []).isEmpty)
        print("Kill-switch exception tests passed")
    }
}
