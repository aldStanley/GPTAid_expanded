char *
pcap_strerror(int errnum){
#ifdef HAVE_STRERROR
#ifdef _WIN32
	static thread_local char errbuf[PCAP_ERRBUF_SIZE];
	errno_t err = strerror_s(errbuf, PCAP_ERRBUF_SIZE, errnum);

	if (err != 0) /* err = 0 if successful */
		pcap_strlcpy(errbuf, "strerror_s() error", PCAP_ERRBUF_SIZE);
	return (errbuf);
#else
	return (strerror(errnum));
#endif /* _WIN32 */
#else
	extern int sys_nerr;
	extern const char *const sys_errlist[];
	static thread_local char errbuf[PCAP_ERRBUF_SIZE];

	if ((unsigned int)errnum < sys_nerr)
		return ((char *)sys_errlist[errnum]);
	(void)snprintf(errbuf, sizeof errbuf, "Unknown error: %d", errnum);
	return (errbuf);
#endif
}
