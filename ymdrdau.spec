Name: ymdrdau
Version: %{DRMSVER}
Release: %{GITBRANCH}_%{GITCOMMIT}%{?dist}
Summary: DRMS Server for YamuDNS

Group: Yamu Tech Co Ltd.
License: GPLv3+
URL: http://www.yamu.com/
Source0: %{name}-%{version}.tar.gz

BuildRequires: info
Requires: info

%description
DRMS Server for YamuDNS

%define debug_package %{nil}

%prep
%setup -q


%build
exit 0
#%configure
#make %{?_smp_mflags}


%install
mkdir -p ${RPM_BUILD_ROOT}/%{_bindir}
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/init.d
mkdir -p ${RPM_BUILD_ROOT}/var/ymdrdau_data

install -m 0755 bin/%{name} ${RPM_BUILD_ROOT}/%{_bindir}/%{name}
install -m 0755 etc/start_fstrm_capture ${RPM_BUILD_ROOT}/%{_bindir}/start_fstrm_capture
install -m 0755 etc/init.d/%{name} ${RPM_BUILD_ROOT}/%{_sysconfdir}/init.d/%{name}
install -m 0644 etc/%{name}.ini ${RPM_BUILD_ROOT}/%{_sysconfdir}/%{name}.ini
install -m 0644 etc/base_library.zip ${RPM_BUILD_ROOT}/var/ymdrdau_data
install -m 0644 etc/local-rootzone ${RPM_BUILD_ROOT}/%{_sysconfdir}/local_root.zone
install -m 0644 etc/std-rootzone ${RPM_BUILD_ROOT}/%{_sysconfdir}/std_root.zone
exit 0

%make_install


%post
if [ "$1" = "1" ]
then
    chkconfig --add ymdrdau
fi


%files
%{_bindir}/%{name}
%{_bindir}/start_fstrm_capture
%{_sysconfdir}/init.d/%{name}
%config%{_sysconfdir}/%{name}.ini
%config%{_sysconfdir}/local_root.zone
%config%{_sysconfdir}/std_root.zone
/var/ymdrdau_data/base_library.zip

%doc


%preun
if [ "$1" = "0" ]
then
    chkconfig --del ymdrdau
fi


%define __debug_install_post   \
%{_rpmconfigdir}/find-debuginfo.sh %{?_find_debuginfo_opts} "%{_builddir}/%{?buildsubdir}"\
%{nil}

%changelog


