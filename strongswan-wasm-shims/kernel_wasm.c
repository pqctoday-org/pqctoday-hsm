/*
 * kernel_wasm.c — Tier A stub kernel_ipsec_t backend for the strongSwan
 * WASM build.
 *
 * The browser has no kernel IPsec stack, so the baseline build forced
 * childless IKE_SAs (RFC 6023): CHILD_SA negotiation aborted at SPI
 * allocation ("unable to allocate SPI from kernel") because
 * kernel_interface_t has no registered kernel_ipsec_t backend and
 * returns NOT_SUPPORTED from get_spi/add_sa/add_policy/...
 *
 * This stub lets a *real* CHILD_SA negotiate over the wire (proposals,
 * nonces, TS, KEYMAT derivation all genuine) while SADB/SPD "installation"
 * is a no-op:
 *
 *   - get_spi      : hands out sequential non-zero SPIs (network order,
 *                    same convention as libipsec's ipsec_sa_mgr)
 *   - add_sa / update_sa / del_sa / flush_sas         : SUCCESS no-ops
 *   - add_policy / del_policy / flush_policies        : SUCCESS no-ops
 *   - query_sa / query_policy                         : zeroed outputs
 *   - get_cpi      : NOT_SUPPORTED (no IPComp)
 *   - bypass_socket / enable_udp_decap                : TRUE no-ops
 *
 * Registration: wasm_kernel_register() is called from wasm_setup_config()
 * (wasm_backend.c) when the hub opts in via WASM_CHILDSA=1. It uses
 * kernel_interface_t::add_ipsec_interface, which instantiates the backend
 * immediately — the same registration path the kernel-netlink/libipsec
 * plugins use via PLUGIN_REGISTER(KERNEL_IPSEC, ...), minus the plugin
 * lifecycle (charon->kernel exists from libcharon_init, and config setup
 * runs before any negotiation).
 *
 * No kernel_net_t stub is provided: every kernel_interface_t net method
 * already degrades gracefully (NULL / empty enumerator / NOT_SUPPORTED)
 * and the WASM build resolves addresses from the hard-coded ike_cfg.
 */

#ifdef __EMSCRIPTEN__

#include <stdlib.h>

#include <daemon.h>
#include <library.h>
#include <utils/debug.h>
#include <kernel/kernel_ipsec.h>
#include <kernel/kernel_interface.h>

typedef struct private_kernel_wasm_ipsec_t private_kernel_wasm_ipsec_t;

struct private_kernel_wasm_ipsec_t {

	/**
	 * Public interface.
	 */
	kernel_ipsec_t public;

	/**
	 * Next SPI to hand out (host order, converted on allocation).
	 */
	uint32_t next_spi;
};

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_wasm_ipsec_t *this)
{
	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_wasm_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	/* Sequential non-zero SPIs in the private range used by libipsec
	 * (0xc0000000+), stored in network byte order like a real kernel
	 * allocator would return them. */
	*spi = htonl(this->next_spi++);
	DBG2(DBG_KNL, "WASM stub kernel: allocated SPI %.8x", ntohl(*spi));
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_wasm_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	DBG2(DBG_KNL, "WASM stub kernel: add_sa SPI %.8x (no-op)",
		 ntohl(id->spi));
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	if (bytes)
	{
		*bytes = 0;
	}
	if (packets)
	{
		*packets = 0;
	}
	if (time)
	{
		*time = 0;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_wasm_ipsec_t *this)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	if (use_time)
	{
		*use_time = 0;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_wasm_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_wasm_ipsec_t *this)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_wasm_ipsec_t *this, int fd, int family)
{
	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_wasm_ipsec_t *this, int fd, int family, uint16_t port)
{
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_wasm_ipsec_t *this)
{
	free(this);
}

/**
 * kernel_ipsec_constructor_t — exact (void) signature, no cast needed
 * (WASM traps on function-pointer signature mismatches).
 */
kernel_ipsec_t *kernel_wasm_ipsec_create(void)
{
	private_kernel_wasm_ipsec_t *this;

	INIT(this,
		.public = {
			.get_features = _get_features,
			.get_spi = _get_spi,
			.get_cpi = _get_cpi,
			.add_sa = _add_sa,
			.update_sa = _update_sa,
			.query_sa = _query_sa,
			.del_sa = _del_sa,
			.flush_sas = _flush_sas,
			.add_policy = _add_policy,
			.query_policy = _query_policy,
			.del_policy = _del_policy,
			.flush_policies = _flush_policies,
			.bypass_socket = _bypass_socket,
			.enable_udp_decap = _enable_udp_decap,
			.destroy = _destroy,
		},
		.next_spi = 0xc0000001,
	);

	DBG1(DBG_KNL, "WASM stub kernel_ipsec backend created");
	return &this->public;
}

/**
 * Register the stub backend on charon's kernel interface. Idempotent —
 * add_ipsec_interface refuses a second backend and we guard locally too.
 * Called from wasm_setup_config() when WASM_CHILDSA=1.
 */
void wasm_kernel_register(void)
{
	static bool registered = FALSE;

	if (registered || !charon || !charon->kernel)
	{
		return;
	}
	if (charon->kernel->add_ipsec_interface(charon->kernel,
											kernel_wasm_ipsec_create))
	{
		registered = TRUE;
		DBG1(DBG_KNL, "WASM stub kernel_ipsec backend registered");
	}
	else
	{
		DBG1(DBG_KNL, "WASM stub kernel_ipsec backend registration FAILED");
	}
}

#endif /* __EMSCRIPTEN__ */
