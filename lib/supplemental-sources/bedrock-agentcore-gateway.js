'use strict';

/**
 * Bedrock AgentCore Gateways.
 *
 * As of this writing, AWS Resource Explorer indexes only
 * bedrock-agentcore:runtime for this service - Gateway, Memory, and Identity
 * are not yet discoverable through it (confirmed against
 * `aws resource-explorer-2 list-supported-resource-types`). This source
 * fills that specific gap using the service's own control-plane API.
 *
 * Retire this file once Resource Explorer adds bedrock-agentcore:gateway to
 * its supported types - delete it, or set enabled: false below. No other
 * file references it by name.
 */

const {
    BedrockAgentCoreControlClient,
    ListGatewaysCommand,
    GetGatewayCommand
} = require('@aws-sdk/client-bedrock-agentcore-control');

module.exports = {
    enabled: true,

    service: 'bedrock-agentcore',
    resourceType: 'bedrock-agentcore:gateway',

    // Reuses the existing AI/ML group and the already-vendored official
    // Bedrock icon rather than introducing anything new.
    group: 'AI/ML',
    icon: 'bedrock',

    // IAM actions this source needs. Documented so operators can confirm the
    // profile they select is allowed to call them; the app grants nothing.
    iamActions: [
        'bedrock-agentcore:ListGateways',
        'bedrock-agentcore:GetGateway'
    ],

    /**
     * Returns items shaped like a Resource Explorer resource, so they merge
     * into the same array as ListResources output and flow through the
     * existing classify/icon/tag/detail pipeline unchanged.
     */
    async list(config) {
        const client = new BedrockAgentCoreControlClient(config);
        const items = [];
        let nextToken;
        do {
            const resp = await client.send(new ListGatewaysCommand({ nextToken }));
            for (const g of resp.items || []) {
                items.push({
                    // GatewaySummary carries no ARN (only gatewayId, name,
                    // status, description, createdAt, updatedAt, authorizerType,
                    // protocolType), so the ARN is composed here. config.accountId
                    // is supplied by the caller - never hardcode or wildcard the
                    // account segment, or the UI reports a fabricated account for
                    // every one of these resources.
                    arn: 'arn:aws:bedrock-agentcore:' + config.region + ':' +
                         config.accountId + ':gateway/' + g.gatewayId,
                    name: g.name || g.gatewayId,
                    resourceType: 'bedrock-agentcore:gateway',
                    service: 'bedrock-agentcore',
                    lastReported: g.updatedAt
                });
            }
            nextToken = resp.nextToken;
        } while (nextToken);
        return items;
    },

    /** Called on-demand when a user clicks a Gateway in the UI. */
    async detail(config, item) {
        const client = new BedrockAgentCoreControlClient(config);
        const gatewayId = item.arn.split('/').pop();
        const gw = await client.send(new GetGatewayCommand({ gatewayIdentifier: gatewayId }));
        return {
            details: {
                'Gateway ID': gw.gatewayId,
                'Name': gw.name,
                'Status': gw.status,
                'URL': gw.gatewayUrl || '-',
                'Authorizer Type': gw.authorizerType || '-',
                'Role ARN': gw.roleArn || '-',
                'Created': gw.createdAt ? new Date(gw.createdAt).toISOString() : '-',
                'Updated': gw.updatedAt ? new Date(gw.updatedAt).toISOString() : '-'
            }
        };
    }
};
