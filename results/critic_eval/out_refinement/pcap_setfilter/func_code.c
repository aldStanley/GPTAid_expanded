int pcap_setfilter(pcap_t *p, struct bpf_program *fp){
	return (p->setfilter_op(p, fp));
}
