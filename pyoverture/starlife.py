import base64
import ipaddress
from enum import Enum
import sys
import pyone
from time import sleep
from collections import OrderedDict
from fabric import Connection
import paramiko
from pyoverture.utils import run_command_ssh_gateway


class VirtualImages(Enum):
    # Apps -> Look for the desired distribution (in this case, "ubuntu" in the searcher and "Ubuntu Minimal 18.04 - KVM
    # -> Click into the cloud icon -> Set up a name, select the local datastore (BSC-EUCC Images) -> Download
    # We use the structure to store the image ID in the store
    # Image datastore EUCANCan -> 120
    # Ubuntu 18.04 - KVM       -> 343
    # PAIRS (IMAGE ID, HYPERVISOR)
    UBUNTU1804KVM = (536, "kvm")


class Description(Enum):
    mb_per_core = 4 * 1024
    amount_of_nodes = 48
    cpus_per_node = 40


class CloudSession:
    def __init__(self, ip, user, password):
        self.one = pyone.OneServer(ip, session=user + ":" + password)
        self.user = user
        self.password = password


class VirtualMachine:
    def __init__(self, template, instance_name, public_ip=None, cloud_session=None, base_user=None):
        self.vm_id = None
        self.one = None
        self.cloud_session = cloud_session
        self.template = template
        self.instance_name = instance_name
        self.public_ip = public_ip
        self.base_user = base_user
        self.private_ip = None
        self.private_key = None

    def instantiate(self, cloud_session=None, reset_image=False, check_name=False):
        if cloud_session is None:
            if self.cloud_session is None:
                raise Exception("To instantiate a VM, it is mandatory to fournish a correct cloud session")
            else:
                cloud_session = self.cloud_session

        self.cloud_session = cloud_session
        one = self.cloud_session.one
        reset_base_image = reset_image

        if check_name:
            vm_list = one.vmpool.info(-1, -1, -1, -1)
            for vm in vm_list.VM:
                if vm.NAME == self.instance_name:
                    self.vm_id = vm.ID
                    print("There is already a virtual machine with the name %s. If you want to ignore it and create a "
                          "new one, set \"check_name\" to False." % self.instance_name)
                    return
        try:
            self.vm_id = one.template.instantiate(self.template.get_id(), self.instance_name)
            return
        except Exception as e:
            if "Cannot get IP/MAC" in e.args[0]:
                vm_list = one.vmpool.info(-1, -1, -1, -1)
                for vm in vm_list.VM:
                    if vm.NAME == self.instance_name:
                        for nic in vm.TEMPLATE["NIC"]:
                            if nic["IP"] == "84.88.186.194":
                                if reset_base_image:
                                    print(
                                        "The supplied IP is already in use by a running VM named %s. We will try to "
                                        "erase it "
                                        "and try again." % self.instance_name)
                                    one.vm.action("terminate-hard", vm.get_ID())
                                    print("Virtual Machine with id %s and name %s still not in state DONE" % (
                                        vm.get_ID(), vm.NAME), end="")
                                    while not (one.vm.info(vm.get_ID()).STATE == 6):
                                        print(".", end="")
                                        sys.stdout.flush()
                                        sleep(1)
                                    print("")
                                    self.vm_id = one.template.instantiate(self.template.get_id(), self.instance_name)
                                    return
                                else:
                                    print(
                                        "The supplied IP is already in use by a running VM named %s. Set reset base "
                                        "image to True if you want to try to erase it and try again. Otherwise, the "
                                        "program will keep going with the machine in the state as it is currently "
                                        "assuming that everything is well configured."
                                        % self.instance_name)
                                    self.vm_id = vm.ID
                                    return
                    else:
                        if isinstance(vm.TEMPLATE["NIC"], OrderedDict):
                            if vm.TEMPLATE["NIC"]["IP"] == "84.88.186.194":
                                print(
                                    "The supplied IP is already in use by a running VM named %s. Since this is not the "
                                    "same name supplied, it cannot be assumed that it is the same machine. If you want "
                                    "to erase it, erase it by hand."
                                    % self.instance_name)
                                raise e
                        else:
                            for nic in vm.TEMPLATE["NIC"]:
                                print(nic)
                                if nic["IP"] == "84.88.186.194":
                                    print(
                                        "The supplied IP is already in use by a running VM named %s. Since this is not "
                                        "the same name supplied, it cannot be assumed that it is the same machine. If "
                                        "you want to erase it, erase it by hand."
                                        % self.instance_name)
                                    raise e
            else:
                raise e

    def run_command(self, command, print_message=None, verbose=False):
        private_ip = self.get_private_ip()
        public_ip_login_node = self.get_public_ip()
        local_private = self.get_local_rsa_private()
        base_user = self.get_base_user()
        conn = Connection(host=public_ip_login_node, user=base_user, connect_kwargs={"key_filename": local_private},
                          forward_agent=True)
        if print_message is not None:
            print(print_message, end="")
        out, err = run_command_ssh_gateway(conn, base_user, private_ip, command)
        if verbose:
            print(out, err)
        conn.close()
        return out, err

    def get_ip_list(self):
        if self.vm_id is None:
            raise Exception("The virtual machine has not been instantiated successfully")
        one = self.cloud_session.one
        vm_list = one.vmpool.info(-1, self.vm_id, self.vm_id, -1)
        # print(vm_list.VM[0].TEMPLATE["NIC"])
        nic_list = vm_list.VM[0].TEMPLATE["NIC"]
        ip_list = []
        if isinstance(nic_list, OrderedDict):
            ip_list.append(nic_list["IP"])
            return ip_list
        for nic in vm_list.VM[0].TEMPLATE["NIC"]:
            ip_list.append(nic["IP"])
        return ip_list

    def get_private_ip(self):
        if self.vm_id is None:
            raise Exception("The virtual machine has not been instantiated successfully")
        ip_list = self.get_ip_list()
        self.private_ip = None
        for ip in ip_list:
            if ip.startswith("10."):
                self.private_ip = ip
                return ip
        raise Exception("There is not a valid private IP assigned")

    def get_public_ip(self):
        if self.public_ip is None:
            raise(Exception("The virtual machine does not have a public IP associated. This is almost for sure because"
                            "it has not been correctly instantiated"))
        return self.public_ip

    def get_local_rsa_private(self):
        return self.private_key

    def get_base_user(self):
        return self.base_user

    def set_vm_conn_private_key(self, private_key):
        self.private_key = private_key

    def run_ssh_command(self, command):
        private_ip = self.get_private_ip()
        public_ip_login_node = self.get_public_ip()
        local_private = self.get_local_rsa_private()
        base_user = self.get_base_user()
        conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                          forward_agent=True)
        out, err = run_command_ssh_gateway(conn, base_user, private_ip, command)
        return out, err

    def power_off(self):
        if self.vm_id is None:
            raise Exception('VM has no session associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        if self.cloud_session is None:
            raise Exception('VM has no id associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        self.vm_id = self.cloud_session.one.vm.action("poweroff", self.cloud_session.one.vmpool.info(-1, self.vm_id,
                                                                                                     self.vm_id,
                                                                                                     -1).VM[0].ID)

    def terminate(self):
        if self.vm_id is None:
            raise Exception('VM has no session associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        if self.cloud_session is None:
            raise Exception('VM has no id associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        self.cloud_session.one.vm.action("terminate", self.cloud_session.one.vmpool.info(-1, self.vm_id, self.vm_id,
                                                                                         -1).VM[0].ID)
        self.vm_id = None

    def set_vm_private_key(self, local_private_key, remote_private_key, public_ip=None):
        if public_ip is None:
            public_ip = self.public_ip
        if self.cloud_session is None:
            raise Exception('VM has no session associated. This is almost sure because it has not been'
                            'successfully instantiated.')
        if public_ip is None:
            raise Exception("VM has no public IP associated. A valid gateway to access to the machine has not been "
                            "supplied")
        if self.base_user is None:
            conn_to_login = Connection(host=public_ip,
                                       connect_kwargs={"key_filename": local_private_key})
        else:
            conn_to_login = Connection(host=public_ip, user=self.base_user,
                                       connect_kwargs={"key_filename": local_private_key})
        conn_to_login.put(local_private_key, remote_private_key)

    def wait_until_running(self, public_ip=None, private_key=None):
        if public_ip is None:
            public_ip = self.public_ip
        if self.cloud_session is None:
            raise Exception('VM has no session associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        if self.vm_id is None:
            raise Exception('VM has no id associated. This is almost sure because it has not been '
                            'successfully instantiated.')
        if public_ip is None:
            raise Exception("VM has no public IP associated. A valid gateway to access to the machine has not been "
                            "supplied")
        one = self.cloud_session.one
        user = self.base_user
        vm_id = self.vm_id
        public_ip = self.public_ip
        if private_key is None:
            private_key = self.private_key

        print("Waiting until vm with id %d and name %s is running"
              % (vm_id, one.vmpool.info(-1, vm_id, vm_id, -1).VM[0].NAME), end="")
        # ACTIVE and RUNNING
        while not (one.vm.info(vm_id).STATE == 3 and one.vm.info(vm_id).LCM_STATE == 3):
            print(".", end="")
            sys.stdout.flush()
            sleep(1)
        print("")

        print("Waiting until vm with id %d and name %s has ssh reachable"
              % (vm_id, one.vmpool.info(-1, vm_id, vm_id, -1).VM[0].NAME), end="")

        keep_trying = True
        connection_args = {}
        if private_key is not None:
            connection_args["connect_kwargs"] = {"key_filename": private_key}
        if user is not None:
            connection_args["user"] = user
        curr_conn = Connection(public_ip, **connection_args)
        while keep_trying:
            print(".", end="")
            sys.stdout.flush()
            try:
                curr_conn.open()
                curr_conn.close()
                keep_trying = False
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                if "Unable to connect to port 22" not in str(e):
                    raise e
            sleep(1)
        print("")


class NIC:
    def __init__(self, cloud_session, network, network_ip=None, network_owner="oneadmin"):
        self.cloud_session = cloud_session
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
    IP = "%s",''' % self.network_ip
        else:
            # Internal network
            vm_int_net_templ = '''NIC = ['''
        vm_int_net_templ += '''
    NETWORK = "%s",
    NETWORK_UNAME = "%s"
]
''' % (self.network, self.network_owner)
        return vm_int_net_templ


class Template:
    def __init__(self, cloud_session, template_name, virtual_image, username, password, cpu, memory, cluster,
                 disk_size=None, hostname=None, ip_forward=None, automount_nfs=None, ssh_public_key=None,
                 additional_users=(), gateway_interface=None, automatic_update=False, graphics=False, nics=()):
        # The cpus fit into a single node
        assert cpu < cluster.cpus_per_node.value

        # Memory has a correct value
        if memory is None:
            memory = cluster.mb_per_core.value * cpu
        else:
            try:
                int(memory)
            except Exception:
                raise ValueError("The given value %s used for the memory is not correct" % memory)

        self.cloud_session = cloud_session
        self.template_name = template_name
        self.virtual_image = virtual_image
        self.cpu = cpu
        self.memory = memory
        self.cluster = cluster
        self.disk_size = disk_size
        self.graphics = graphics
        self.nics = nics
        self.context = Context(username, password, hostname=hostname, ip_forward=ip_forward,
                               automount_nfs=automount_nfs, ssh_public_key=ssh_public_key,
                               additional_users=additional_users,
                               gateway_interface=gateway_interface, automatic_update=automatic_update)
        self.template_id = None

    def allocate_template(self, overwrite=False):
        one = self.cloud_session.one
        vm_template = one.templatepool.info(-1, -1, -1).VMTEMPLATE
        # Check if a template already exists with this name
        for elem in vm_template:
            if elem.get_NAME() == self.template_name:
                if overwrite:
                    print("Erasing existant template with name \"%s\"" % self.template_name, file=sys.stderr)
                    one.template.delete(elem.get_ID())
                else:
                    raise Exception("A template with name \"%s\" already exists" % self.template_name)

        self.template_id = one.template.allocate(self.get_full_template())

    def get_machine_description(self):
        # Build the base open nebula template
        vm_templ = '''NAME = "%s"
DISK=[ IMAGE_ID = %d''' % (self.template_name, self.virtual_image.value[0])
        if self.disk_size is not None:
            vm_templ += ''' ,
SIZE=%s''' % self.disk_size
        vm_templ += ''' ]
CPU = %d
MEMORY = %d
MEMORY_UNIT_COST = "MB"
''' % (self.cpu, self.memory)
        if self.virtual_image.value[1] is not None:
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

    def get_id(self):
        return self.template_id


class Context:
    def __init__(self, username, password, hostname=None, ip_forward=None, automount_nfs=None, ssh_public_key=None,
                 additional_users=(), gateway_interface=None, automatic_update=False):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.ip_forward = ip_forward
        self.automount_nfs = automount_nfs
        self.ssh_public_key = ssh_public_key
        self.additional_users = additional_users
        self.gateway_interface = gateway_interface
        self.automatic_update = automatic_update

    @staticmethod
    def _generate_ip_forward(public_interface, private_interface):
        return "sysctl net.ipv4.ip_forward=1; iptables -A FORWARD -i " + private_interface + " -j ACCEPT; iptables -t" \
                                                                                             " nat -o " + \
               public_interface + " -A POSTROUTING -j MASQUERADE;"

    @staticmethod
    def _generate_automount_nfs(nfs_ip, nfs_origin, nfs_mount_point):
        ipaddress.ip_address(nfs_ip)
        return "mkdir -p /etc/auto.master.d;echo \"/-\t/etc/auto.direct\" > /etc/auto.master.d/direct.autofs;echo \"" \
               + \
               nfs_mount_point + "\t-rw,noatime,rsize=1048576,wsize=1048576,nolock,intr,tcp,actimeo=1800\t" + nfs_ip + \
               ":" + nfs_origin + "\" > /etc/auto.direct; /etc/init.d/autofs restart;"

    @staticmethod
    def _generate_disable_automatic_update():
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
        if self.gateway_interface is not None:
            context_templ += """
    GATEWAY_IFACE = "ETH%d",""" % self.gateway_interface
        if self.ssh_public_key is not None:
            context_templ += """
    SSH_PUBLIC_KEY = "%s",
""" % self.ssh_public_key

        command_to_execute = ""
        if self.ip_forward is not None:
            public, private = self.ip_forward
            command_to_execute += Context._generate_ip_forward(public, private)
        if self.automount_nfs is not None:
            nfs_ip, nfs_origin, nfs_mount_point = self.automount_nfs
            command_to_execute += Context._generate_automount_nfs(nfs_ip, nfs_origin, nfs_mount_point)
        if not self.automatic_update:
            command_to_execute += Context._generate_disable_automatic_update()
        if not (command_to_execute == ""):
            context_templ += """    START_SCRIPT_BASE64 = "%s"
""" % base64.b64encode(command_to_execute.encode("utf-8")).decode("utf-8")
        context_templ = context_templ[:-1] + "]"
        return context_templ
