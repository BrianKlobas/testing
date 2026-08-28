import os
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient

def collect_azure_inventory():
    # Authenticate using DefaultAzureCredential (supports CLI, environment variables, managed identity)
    credential = DefaultAzureCredential()
    
    # Initialize subscription client to find all accessible accounts/subscriptions
    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())
    
    print(f"Found {len(subscriptions)} accessible subscription(s). Starting collection...")

    # Create local directory for outputs
    output_dir = "azure_inventory"
    os.makedirs(output_dir, exist_ok=True)

    for sub in subscriptions:
        sub_id = sub.subscription_id
        sub_name = sub.display_name
        print(f"Processing subscription: {sub_name} ({sub_id})")

        sub_data = {
            "subscription_id": sub_id,
            "subscription_name": sub_name,
            "state": sub.state,
            "resource_groups": [],
            "resources": []
        }

        try:
            # Initialize Resource Management Client for the current subscription
            resource_client = ResourceManagementClient(credential, sub_id)

            # Collect Resource Groups
            groups = resource_client.resource_groups.list()
            for rg in groups:
                sub_data["resource_groups"].append({
                    "name": rg.name,
                    "location": rg.location,
                    "tags": rg.tags,
                    "provisioning_state": rg.provisioning_state
                })

            # Collect All Resources within the subscription
            resources = resource_client.resources.list()
            for res in resources:
                sub_data["resources"].append(res.as_dict())

        except Exception as e:
            print(f"Error processing subscription {sub_name}: {str(e)}")
            sub_data["error"] = str(e)

        # Sanitize subscription name for filename use
        safe_sub_name = "".join(c if c.isalnum() else "_" for c in sub_name)
        filename = os.path.join(output_dir, f"{safe_sub_name}_{sub_id}.json")

        # Save subscription data into its own JSON file
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sub_data, f, indent=4, default=str)
        
        print(f"Saved inventory to {filename}")

if __name__ == "__main__":
    collect_azure_inventory()
