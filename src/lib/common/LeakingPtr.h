/*
 * LeakingPtr.h
 *
 * A minimal owning smart pointer for PROCESS-LIFETIME singletons.
 *
 * It exposes the same {get, reset, operator->, operator*} surface as
 * std::unique_ptr for the subset SoftHSM's singletons use, with ONE
 * deliberate difference: its destructor does NOT delete the managed object.
 * This intentionally "leaks" the singleton at process exit so it survives
 * C++ static-destruction ordering.
 *
 * Why this exists
 * ---------------
 * OpenSSL registers OPENSSL_cleanup via atexit(). When a PKCS#11 consumer
 * (e.g. our pkcs11-provider) is torn down inside that atexit handler, it can
 * call back into this module (C_CloseSession / C_Finalize). C++ static
 * destructors run before atexit handlers that were registered earlier, so by
 * the time OPENSSL_cleanup runs the SoftHSM/MutexFactory/crypto-factory
 * singletons may already be destroyed. Those late callbacks then dereference
 * freed memory -> intermittent SIGSEGV (e.g. HandleManager::getSessionShared
 * via SoftHSM::C_CloseSession during ossl_provider_free).
 *
 * Leaking the singletons keeps the module valid until the process is fully
 * gone; the OS reclaims the memory. A module that crashes the host process at
 * cleanup is far worse than one that leaks a handful of objects at exit.
 *
 * reset() STILL deletes the previous object, so explicit teardown
 * (C_Finalize -> SoftHSM::reset(), fork handling) does not leak.
 */

#ifndef _SOFTHSM_V2_LEAKINGPTR_H
#define _SOFTHSM_V2_LEAKINGPTR_H

#include <cstddef>

template <typename T>
class LeakingPtr
{
public:
	explicit LeakingPtr(T* ptr = NULL) : p(ptr) { }

	// Intentionally does NOT delete p: the singleton must outlive
	// C++ static destruction so late atexit callbacks stay valid.
	~LeakingPtr() { }

	T* get() const { return p; }
	T* operator->() const { return p; }
	T& operator*() const { return *p; }

	// Mirror std::unique_ptr's explicit bool conversion so existing call
	// sites like `if (!instance)` / `if (instance)` keep working unchanged.
	explicit operator bool() const { return p != NULL; }

	// Explicit lifetime management DOES free, so C_Finalize/fork do not leak.
	void reset(T* ptr = NULL)
	{
		if (p != ptr)
		{
			delete p;
			p = ptr;
		}
	}

	T* release()
	{
		T* old = p;
		p = NULL;
		return old;
	}

private:
	LeakingPtr(const LeakingPtr&);
	LeakingPtr& operator=(const LeakingPtr&);

	T* p;
};

#endif // !_SOFTHSM_V2_LEAKINGPTR_H
