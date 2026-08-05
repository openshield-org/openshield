#!/bin/bash

set -euo pipefail

echo "Azure DevOps service connections cannot have their scope changed in place; the"
echo "Azure CLI and REST API only support deleting and re-creating them."
echo
echo "1. Identify which pipelines actually need this service connection:"
echo "   az pipelines list --project <project>"
echo
echo "2. Create a new service connection scoped to only the resource group each"
echo "   pipeline needs, instead of the whole subscription:"
echo "   az devops service-endpoint azurerm create \\"
echo "     --azure-rm-service-principal-id <spn-id> \\"
echo "     --azure-rm-subscription-id <sub-id> \\"
echo "     --azure-rm-subscription-name <sub-name> \\"
echo "     --azure-rm-tenant-id <tenant-id> \\"
echo "     --name <new-connection-name> \\"
echo "     --project <project>"
echo
echo "3. Update each pipeline's YAML or classic definition to reference the new,"
echo "   narrowly scoped connection instead of the shared subscription-wide one."
echo
echo "4. Once no pipeline references the old connection, delete it:"
echo "   az devops service-endpoint delete --id <old-connection-id> --project <project> --yes"
