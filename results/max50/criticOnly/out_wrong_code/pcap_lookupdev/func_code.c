char *
pcap_lookupdev(char *errbuf){
	pcap_if_t *alldevs;
#ifdef _WIN32
  /*
   * Windows - use the same size as the old WinPcap 3.1 code.
   * XXX - this is probably bigger than it needs to be.
   */
  #define IF_NAMESIZE 8192
#else
  /*
   * UN*X - use the system's interface name size.
   * XXX - that might not be large enough for capture devices
   * that aren't regular network interfaces.
   */
#endif
	static char device[IF_NAMESIZE + 1];
	char *ret;

	/*
	 * We disable this in "new API" mode, because 1) in WinPcap/Npcap,
	 * it may return UTF-16 strings, for backwards-compatibility
	 * reasons, and we're also disabling the hack to make that work,
	 * for not-going-past-the-end-of-a-string reasons, and 2) we
	 * want its behavior to be consistent.
	 *
	 * In addition, it's not thread-safe, so we've marked it as
	 * deprecated.
	 */
	if (pcap_new_api) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "pcap_lookupdev() is deprecated and is not supported in programs calling pcap_init()");
		return (NULL);
	}

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		return (NULL);

	if (alldevs == NULL || (alldevs->flags & PCAP_IF_LOOPBACK)) {
		/*
		 * There are no devices on the list, or the first device
		 * on the list is a loopback device, which means there
		 * are no non-loopback devices on the list.  This means
		 * we can't return any device.
		 *
		 * XXX - why not return a loopback device?  If we can't
		 * capture on it, it won't be on the list, and if it's
		 * on the list, there aren't any non-loopback devices,
		 * so why not just supply it as the default device?
		 */
		(void)pcap_strlcpy(errbuf, "no suitable device found",
		    PCAP_ERRBUF_SIZE);
		ret = NULL;
	} else {
		/*
		 * Return the name of the first device on the list.
		 */
		(void)pcap_strlcpy(device, alldevs->name, sizeof(device));
		ret = device;
	}

	pcap_freealldevs(alldevs);
	return (ret);
}
