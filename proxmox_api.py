from proxmoxer import ProxmoxAPI

def create_lxc_instance(vmid, hostname, cpu_cores, memory, disk_size):
    proxmox = ProxmoxAPI('YOUR_PROXMOX_IP', user='YOUR_USER@pam', password='YOUR_PASSWORD', verify_ssl=False)
    
    # Create a new LXC container
    proxmox.nodes('YOUR_NODE_NAME').lxc.create(
        vmid=vmid,
        hostname=hostname,
        ostemplate='local:vztmpl/debian-10-standard_10.7-1_amd64.tar.gz',  # Example template
        memory=memory,
        cores=cpu_cores,
        net0='name=eth0,bridge=vmbr0,ip=dhcp',
        rootfs=f'local-lvm:{disk_size}G',
        password='yourpassword',  # You may want to generate this or take from user input
        unprivileged=1,
    )
