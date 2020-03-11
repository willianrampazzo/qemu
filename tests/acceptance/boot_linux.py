# Functional test that boots a complete Linux system via a cloud image
#
# Copyright (c) 2018-2020 Red Hat, Inc.
#
# Author:
#  Cleber Rosa <crosa@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or
# later.  See the COPYING file in the top-level directory.

import os
import re

from avocado_qemu import Test, BUILD_DIR, SSH_KEY_FROM_QEMU_SOURCE

from qemu.accel import kvm_available
from qemu.accel import tcg_available

from avocado.utils import cloudinit
from avocado.utils import network
from avocado.utils import ssh
from avocado.utils import vmimage
from avocado.utils import datadrainer
from avocado.utils.path import find_command

ACCEL_NOT_AVAILABLE_FMT = "%s accelerator does not seem to be available"
KVM_NOT_AVAILABLE = ACCEL_NOT_AVAILABLE_FMT % "KVM"
TCG_NOT_AVAILABLE = ACCEL_NOT_AVAILABLE_FMT % "TCG"


class BootLinux(Test):
    """
    Boots a Linux system, checking for a successful initialization
    """

    timeout = 900
    chksum = None
    guest_user = 'user01'
    guest_password = 'password'
    #: Whether configure a network interface for ssh connection.
    enable_ssh = False
    #: Localhost address.
    ssh_host = '127.0.0.1'
    #: Localhost port for ssh connection to the guest.
    ssh_port = None
    #: SSH public key file path
    ssh_pub_key = None
    #: SSH private key file path
    ssh_pvt_key = None

    def setUp(self):
        super(BootLinux, self).setUp()
        self.vm.add_args('-smp', '2')
        self.vm.add_args('-m', '1024')
        self.prepare_boot()
        self.prepare_cloudinit()
        if self.enable_ssh:
            self.prepare_ssh()
        # Hold a ssh session to the guest.
        self._ssh_session = None

    def prepare_boot(self):
        self.log.debug('Looking for and selecting a qemu-img binary to be '
                       'used to create the bootable snapshot image')
        # If qemu-img has been built, use it, otherwise the system wide one
        # will be used.  If none is available, the test will cancel.
        qemu_img = os.path.join(BUILD_DIR, 'qemu-img')
        if not os.path.exists(qemu_img):
            qemu_img = find_command('qemu-img', False)
        if qemu_img is False:
            self.cancel('Could not find "qemu-img", which is required to '
                        'create the bootable image')
        vmimage.QEMU_IMG = qemu_img

        self.log.info('Downloading/preparing boot image')
        # Fedora 31 only provides ppc64le images
        image_arch = self.arch
        if image_arch == 'ppc64':
            image_arch = 'ppc64le'
        try:
            self.boot = vmimage.get(
                'fedora', arch=image_arch, version='31',
                checksum=self.chksum,
                algorithm='sha256',
                cache_dir=self.cache_dirs[0],
                snapshot_dir=self.workdir)
            self.vm.add_args('-drive', 'file=%s' % self.boot.path)
        except:
            self.cancel('Failed to download/prepare boot image')

    def prepare_cloudinit(self):
        if self.ssh_pub_key is None:
            (self.ssh_pub_key, self.ssh_pvt_key) = self.default_ssh_key_pair()
        with open(self.ssh_pub_key, 'r') as key_file:
            authorized_key = key_file.readline().strip()
        self.log.info('Set SSH public key: %s' % self.ssh_pub_key)

        self.log.info('Preparing cloudinit image')
        try:
            cloudinit_iso = os.path.join(self.workdir, 'cloudinit.iso')
            self.phone_home_port = network.find_free_port()
            cloudinit.iso(cloudinit_iso, self.name,
                          username=self.guest_user,
                          password=self.guest_password,
                          authorized_key=authorized_key,
                          # QEMU's hard coded usermode router address
                          phone_home_host='10.0.2.2',
                          phone_home_port=self.phone_home_port)
            self.vm.add_args('-drive', 'file=%s,format=raw' % cloudinit_iso)
        except Exception:
            self.cancel('Failed to prepared cloudinit image')

    def launch_and_wait(self):
        self.vm.set_console()
        self.vm.launch()
        console_drainer = datadrainer.LineLogger(self.vm.console_socket.fileno(),
                                                 logger=self.log.getChild('console'))
        console_drainer.start()
        self.log.info('VM launched, waiting for boot confirmation from guest')
        cloudinit.wait_for_phone_home(('0.0.0.0', self.phone_home_port), self.name)

    def default_ssh_key_pair(self):
        """
        Get a pair of public/private ssh keys.

        Lookup for a suitable pair of ssh keys using the heuristic:
        - First check the test parameter 'authorized_key' was
          given
        - Otherwise get the keys versioned in QEMU's source code

        Assume public key filename end with '.pub' and the counterpart
        private key file is in the same directory.
        """
        pub_key = self.params.get('authorized_key',
                                  default=SSH_KEY_FROM_QEMU_SOURCE)

        if not os.path.isfile(pub_key):
            self.cancel("ssh public key %s not exist" % pub_key)

        # Expect private key same path but without .pub name extension.
        pvt_key = re.sub('.pub$', '', pub_key)
        if not os.path.isfile(pvt_key):
            self.cancel("ssh private key %s not exist" % pvt_key)

        return (pub_key, pvt_key)

    def prepare_ssh(self):
        """
        Configure a network interface on guest that forwards port 22
        to `self.ssh_port` port on localhost.
        """
        self.ssh_port = network.find_free_port()
        self.vm.add_args('-netdev',
                         'user,id=user,hostfwd=tcp:%s:%d-:22' % (self.ssh_host,
                                                                 self.ssh_port))
        self.vm.add_args('-device', 'virtio-net-pci,netdev=user')
        self.log.info('Prepared for ssh connection on %s:%s' % (self.ssh_host,
                                                                self.ssh_port))

    @property
    def ssh_session(self):
        """
        Get the SSH session to the guest.
        """
        if self._ssh_session is None:
            session = ssh.Session(self.ssh_host, self.ssh_port,
                                  user=self.guest_user, key=self.ssh_pvt_key)
            if not session.connect():
                self.fail('Unabled to establish an ssh session to the guest')
            self._ssh_session = session
        return self._ssh_session

    def tearDown(self):
        if self._ssh_session:
            self._ssh_session.quit()
        super(BootLinux, self).tearDown()


class BootLinuxX8664(BootLinux):
    """
    :avocado: tags=arch:x86_64
    """

    chksum = 'e3c1b309d9203604922d6e255c2c5d098a309c2d46215d8fc026954f3c5c27a0'

    def test_pc_i440fx_tcg(self):
        """
        :avocado: tags=machine:pc
        :avocado: tags=accel:tcg
        """
        if not tcg_available(self.qemu_bin):
            self.cancel(TCG_NOT_AVAILABLE)
        self.vm.add_args("-accel", "tcg")
        self.launch_and_wait()

    def test_pc_i440fx_kvm(self):
        """
        :avocado: tags=machine:pc
        :avocado: tags=accel:kvm
        """
        if not kvm_available(self.arch, self.qemu_bin):
            self.cancel(KVM_NOT_AVAILABLE)
        self.vm.add_args("-accel", "kvm")
        self.launch_and_wait()

    def test_pc_q35_tcg(self):
        """
        :avocado: tags=machine:q35
        :avocado: tags=accel:tcg
        """
        if not tcg_available(self.qemu_bin):
            self.cancel(TCG_NOT_AVAILABLE)
        self.vm.add_args("-accel", "tcg")
        self.launch_and_wait()

    def test_pc_q35_kvm(self):
        """
        :avocado: tags=machine:q35
        :avocado: tags=accel:kvm
        """
        if not kvm_available(self.arch, self.qemu_bin):
            self.cancel(KVM_NOT_AVAILABLE)
        self.vm.add_args("-accel", "kvm")
        self.launch_and_wait()


class BootLinuxAarch64(BootLinux):
    """
    :avocado: tags=arch:aarch64
    :avocado: tags=machine:virt
    :avocado: tags=machine:gic-version=2
    """

    chksum = '1e18d9c0cf734940c4b5d5ec592facaed2af0ad0329383d5639c997fdf16fe49'

    def add_common_args(self):
        self.vm.add_args('-bios',
                         os.path.join(BUILD_DIR, 'pc-bios',
                                      'edk2-aarch64-code.fd'))
        self.vm.add_args('-device', 'virtio-rng-pci,rng=rng0')
        self.vm.add_args('-object', 'rng-random,id=rng0,filename=/dev/urandom')

    def test_virt_tcg(self):
        """
        :avocado: tags=accel:tcg
        :avocado: tags=cpu:max
        """
        if not tcg_available(self.qemu_bin):
            self.cancel(TCG_NOT_AVAILABLE)
        self.vm.add_args("-accel", "tcg")
        self.vm.add_args("-cpu", "max")
        self.vm.add_args("-machine", "virt,gic-version=2")
        self.add_common_args()
        self.launch_and_wait()

    def test_virt_kvm(self):
        """
        :avocado: tags=accel:kvm
        :avocado: tags=cpu:host
        """
        if not kvm_available(self.arch, self.qemu_bin):
            self.cancel(KVM_NOT_AVAILABLE)
        self.vm.add_args("-accel", "kvm")
        self.vm.add_args("-cpu", "host")
        self.vm.add_args("-machine", "virt,gic-version=2")
        self.add_common_args()
        self.launch_and_wait()


class BootLinuxPPC64(BootLinux):
    """
    :avocado: tags=arch:ppc64
    """

    chksum = '7c3528b85a3df4b2306e892199a9e1e43f991c506f2cc390dc4efa2026ad2f58'

    def test_pseries_tcg(self):
        """
        :avocado: tags=machine:pseries
        :avocado: tags=accel:tcg
        """
        if not tcg_available(self.qemu_bin):
            self.cancel(TCG_NOT_AVAILABLE)
        self.vm.add_args("-accel", "tcg")
        self.launch_and_wait()


class BootLinuxS390X(BootLinux):
    """
    :avocado: tags=arch:s390x
    """

    chksum = '4caaab5a434fd4d1079149a072fdc7891e354f834d355069ca982fdcaf5a122d'

    def test_s390_ccw_virtio_tcg(self):
        """
        :avocado: tags=machine:s390-ccw-virtio
        :avocado: tags=accel:tcg
        """
        if not tcg_available(self.qemu_bin):
            self.cancel(TCG_NOT_AVAILABLE)
        self.vm.add_args("-accel", "tcg")
        self.launch_and_wait()
