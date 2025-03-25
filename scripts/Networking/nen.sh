# New Exit Node for TailScale
function nen() {
        current=`tailscale exit-node list | grep -i 'selected' | cut -f 2 -d ' ' | tr -d '\n'`
        if [ -z $current ]; then
                current="NONE"
        fi
        n=`tailscale exit-node list --filter=USA | grep -v 'selected' | grep -v "$current" | cut -f 2 -d ' ' | uniq | sort -R | head -n 1`
        echo "Setting new Exit Node to $n..."
        tailscale set --exit-node=$(echo -n "$n") --exit-node-allow-lan-access
        curl -sSL ipv4.icanhazip.com
}

# Remove Exit Node for TailScale
function nenoff() {
        tailscale set --exit-node= --exit-node-allow-lan-access
        echo "Disabling Exit Node"
        curl -sSL ipv4.icanhazip.com
}