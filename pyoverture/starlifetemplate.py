import base64
import ipaddress
from enum import Enum


class VirtualImages(Enum):
    #  Apps -> Look for the desired distribution (in this case, "ubuntu" in the searcher and "Ubuntu Minimal 18.04 - KVM
    #  -> Click into the cloud icon -> Set up a name, select the local datastore (BSC-EUCC Images) -> Download
    ## We use the structure to store the image ID in the store
    #  Image datastore EUCANCan -> 120
    #  Ubuntu 18.04 - KVM       -> 343
    ## PAIRS (IMAGE ID, HYPERVISOR)
    UBUNTU1804KVM = (536, "kvm")


class Description(Enum):
    mb_per_core = 4 * 1024
    amount_of_nodes = 48
    cpus_per_node = 40


class NIC():
    def __init__(self, one, network, network_ip=None, network_owner="oneadmin"):
        self.one = one
        self.network = network
        if network_ip is None:
            self.network_ip = network_ip
        else:
            ipaddress.ip_address(network_ip)
            self.network_ip = network_ip
        self.network_owner = network_owner

    def get_nic_description(self):
        if self.network_ip is not None:
            vm_int_net_templ = '''NIC = [
    IP = "%s",''' % (self.network_ip)
        else:
            ## Internal network
            vm_int_net_templ = '''NIC = ['''
        vm_int_net_templ += '''
    NETWORK = "%s",
    NETWORK_UNAME = "%s"
]
''' % (self.network, self.network_owner)
        return vm_int_net_templ


class Template():
    def __init__(self, one, template_name, virtual_image, username, password, cpu, memory, cluster,
                 disk_size=None, hostname=None, ip_forward=None, automount_nfs=None, ssh_public_key=None,
                 additional_users=[], gateway_interface=None, automatic_update=False, graphics=False, nics=[]):
        ## The cpus fit into a single node
        assert (cpu < cluster.cpus_per_node.value)

        ## Memory has a correct value
        if memory is None:
            memory = cluster.mb_per_core.value * cpu
        else:
            try:
                int(memory)
            except:
                raise ValueError("The given value %s used for the memory is not correct" % (memory))

        self.one = one
        self.template_name = template_name
        self.virtual_image = virtual_image
        self.cpu = cpu
        self.memory = memory
        self.cluster = cluster
        self.disk_size = disk_size
        self.graphics = graphics
        self.nics = nics
        self.context = Context(one, username, password, hostname=hostname, ip_forward=ip_forward,
                               automount_nfs=automount_nfs, ssh_public_key=ssh_public_key,
                               additional_users=additional_users,
                               gateway_interface=gateway_interface, automatic_update=automatic_update)

    def get_machine_description(self):
        ## Build the base open nebula template
        vm_templ = '''NAME = "%s"
DISK=[ IMAGE_ID = %d''' % (self.template_name, self.virtual_image.value[0])
        if not self.disk_size is None:
            vm_templ += ''' ,
SIZE=%s''' % (self.disk_size)
        vm_templ += ''' ]
CPU = %d
MEMORY = %d
MEMORY_UNIT_COST = "MB"
''' % (self.cpu, self.memory)
        if not self.virtual_image.value[1] is None:
            vm_templ += '''HYPERVISOR = "%s"
''' % (self.virtual_image.value[1])
        return vm_templ

    def get_full_template(self):
        template = self.get_machine_description() + self.context.get_context()
        # This enables connecting to the VM through sunstone
        for current_nic in self.nics:
            template += current_nic.get_nic_description()
        if self.graphics:
            template += """    
        GRAPHICS = [
            LISTEN = "0.0.0.0",
            TYPE = "vnc"]"""
        return template


class Context():
    def __init__(self, one, username, password, hostname=None, ip_forward=None, automount_nfs=None, ssh_public_key=None,
                 additional_users=[], gateway_interface=None, automatic_update=False):
        self.one = one
        self.username = username
        self.password = password
        self.hostname = hostname
        self.ip_forward = ip_forward
        self.automount_nfs = automount_nfs
        self.ssh_public_key = ssh_public_key
        self.additional_users = additional_users
        self.gateway_interface = gateway_interface
        self.automatic_update = automatic_update

    def _generate_ip_forward(self, public_interface, private_interface):
        return "sysctl net.ipv4.ip_forward=1; iptables -A FORWARD -i " + private_interface + " -j ACCEPT; iptables -t " \
                                                                                             "" \
                                                                                             "nat -o " + \
               public_interface + " -A POSTROUTING -j MASQUERADE;"

    def _generate_automount_nfs(self, nfs_ip, nfs_origin, nfs_mount_point):
        ipaddress.ip_address(nfs_ip)
        return "mkdir -p /etc/auto.master.d;echo \"/-\t/etc/auto.direct\" > /etc/auto.master.d/direct.autofs;echo \"" \
               + \
               nfs_mount_point + "\t-rw,noatime,rsize=1048576,wsize=1048576,nolock,intr,tcp,actimeo=1800\t" + nfs_ip + \
               ":" + nfs_origin + "\" > /etc/auto.direct; /etc/init.d/autofs restart;"

    def _generate_disable_automatic_update(self):
        return "sed -i 's/APT::Periodic::Update-Package-Lists \"1\";/APT::Periodic::Update-Package-Lists \"0\";/g' " \
               "/etc/apt/apt.conf.d/20auto-upgrades;" \
               "sed -i 's/APT::Periodic::Unattended-Upgrade \"1\";/APT::Periodic::Unattended-Upgrade \"0\";/g' " \
               "/etc/apt/apt.conf.d/20auto-upgrades;"

    def get_context(self):
        if self.hostname is None:
            self.hostname = '$NAME.vm.bsc.es'
        context_templ = """CONTEXT = [
    USERNAME = "%s",
    PASSWORD = "%s",
    SET_HOSTNAME = "%s",
    NETWORK = "YES",""" % (self.username, self.password, self.hostname)
        if not self.gateway_interface is None:
            context_templ += """
    GATEWAY_IFACE = "ETH%d",""" % (self.gateway_interface)
        if not self.ssh_public_key is None:
            context_templ += """
    SSH_PUBLIC_KEY = "%s",
""" % (self.ssh_public_key)

        command_to_execute = ""
        if not self.ip_forward is None:
            public, private = self.ip_forward
            command_to_execute += self._generate_ip_forward(public, private)
        if not self.automount_nfs is None:
            nfs_ip, nfs_origin, nfs_mount_point = self.automount_nfs
            command_to_execute += self._generate_automount_nfs(nfs_ip, nfs_origin, nfs_mount_point)
        if not self.automatic_update:
            command_to_execute += self._generate_disable_automatic_update()
        if not (command_to_execute == ""):
            context_templ += """    START_SCRIPT_BASE64 = "%s"
""" % (base64.b64encode(command_to_execute.encode("utf-8")).decode("utf-8"))
            context_templ
        context_templ = context_templ[:-1] + "]"
        return context_templ
