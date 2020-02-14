# CPU hotplug acceptance test.
#
# Copyright (c) 2020 Red Hat, Inc.
#
# Author:
#  Wainer dos Santos Moschetta <wainersm@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or
# later.  See the COPYING file in the top-level directory.

"""
Provides tests for CPU hotplug/unplug.
"""
import re

from boot_linux import BootLinux
from qemu.accel import kvm_available


class CPUHotplug(BootLinux):
    """
    CPU hotplug testsuite.
    """
    enable_ssh = True
    # It needs admin priviledges to set cpu online.
    guest_user = 'root'

    def guest_cpu_num(self):
        """
        Get the number of online cpus.
        """
        cpuinfo = self.ssh_session.cmd('cat /proc/cpuinfo')
        if cpuinfo.exit_status != 0:
            if cpuinfo.exit_status == 255:
                self.fail('SSH connection refused')
            else:
                self.fail('Failed to count number of guest cpus')
        procs = re.findall(r'processor\t: \d+', cpuinfo.stdout_text)
        return len(procs)

    def guest_set_cpu_online(self, cpu_num):
        """
        Set cpu online.
        """
        ret = self.ssh_session.cmd("echo 1 > "
                                   "/sys/devices/system/cpu"
                                   "/cpu%s/online" % cpu_num)
        if ret.exit_status != 0:
            self.fail("Failed to set cpu%s online" % cpu_num)

    def test_x86_64_kvm(self):
        """
        Launch the VM with only one cpu and then hotplug the remaining
        up to maximum allowed.

        :avocado: tags=machine:q35
        :avocado: tags=arch:x86_64
        :avocado: tags=accel:kvm
        :avocado: tags=hotplug,cpu
        """
        if not kvm_available(self.arch, self.qemu_bin):
            self.cancel('KVM is not available')

        max_cpus = self.params.get('maxcpus', default=4)
        self.vm.add_args('-accel', 'kvm')
        self.vm.add_args('-cpu', 'host')
        self.vm.add_args('-smp', '1,maxcpus=%s' % max_cpus)

        self.launch_and_wait()

        hotpluggable_cpus = self.vm.command('query-hotpluggable-cpus')
        self.assertEqual(len(hotpluggable_cpus), max_cpus,
                         "Expected maximum of hotpluggable CPUs")
        self.assertEqual(self.guest_cpu_num(), 1,
                         'Start the VM with one CPU only')

        # Hotplugging up to maximum allowed.
        #
        i = 1
        for cpu in hotpluggable_cpus:
            if 'qom-path' in cpu:
                # CPU0 is already online.
                continue
            # Hotplug the CPU.
            self.vm.command('device_add', id=i,
                            socket_id=cpu['props']['socket-id'],
                            core_id=cpu['props']['core-id'],
                            thread_id=cpu['props']['thread-id'],
                            driver=cpu['type'])
            # Set CPU online on guest.
            self.guest_set_cpu_online(i)
            i += 1
            self.assertEqual(self.guest_cpu_num(), i,
                             "Expected CPUs after hotpluged one more")
