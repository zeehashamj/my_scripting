#!/bin/bash

# Check if there are any packages needing configuration
rm -f /etc/apt/sources.list.d/imunify-cloudways.list
apt-get update

UNCONFIGURED=$(dpkg --audit)

if [ -n "$UNCONFIGURED" ]; then
    echo "⚠️ Unconfigured packages detected:"
    echo "$UNCONFIGURED"
    echo "⏳ Running 'dpkg --configure -a' to fix..."

    # Run the fix
    sudo dpkg --configure -a

    if [ $? -eq 0 ]; then
        echo "✅ All packages configured successfully."
    else
        echo "❌ There was an error while configuring packages."
        exit 1
    fi
else
    echo "✅ No issues found. All packages are properly configured."
fi

echo "✅ Running firewall upgrade."
/etc/cron.daily/imunify360-firewall /dev/stdout
if [ $? -eq 0 ]; then
    echo "✅ firewall upgraded successfully."
else
    echo "❌ Firewall upgrade has failed...."
fi
