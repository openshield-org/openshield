#!/bin/bash

set -euo pipefail

echo "Azure DevOps service connections cannot have their authentication scheme"
echo "changed in place; a password-based connection must be re-created as federated."
echo
echo "1. Create a new service connection using workload identity federation:"
echo "   az devops service-endpoint azurerm create \\"
echo "     --azure-rm-service-principal-id <spn-id> \\"
echo "     --azure-rm-subscription-id <sub-id> \\"
echo "     --azure-rm-subscription-name <sub-name> \\"
echo "     --azure-rm-tenant-id <tenant-id> \\"
echo "     --service-principal-type federated \\"
echo "     --name <new-connection-name> \\"
echo "     --project <project>"
echo
echo "   (Federated auth is also available directly in the Azure DevOps UI:"
echo "   Project Settings > Service connections > New service connection >"
echo "   Azure Resource Manager > Workload identity federation.)"
echo
echo "2. Update each pipeline's YAML or classic definition to reference the new,"
echo "   federated connection instead of the password-based one."
echo
echo "3. Once no pipeline references the old connection, delete it and revoke the"
echo "   underlying service principal secret it depended on:"
echo "   az devops service-endpoint delete --id <old-connection-id> --project <project> --yes"
