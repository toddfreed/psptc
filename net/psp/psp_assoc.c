// SPDX-License-Identifier: GPL-2.0-only
/* PSP associations which are not bound to a socket.
 *
 * They are created and deleted over netlink, and referenced by ID by other
 * kernel users, e.g. the tc psp action. The registry holds one reference
 * on each published association.
 */

#include <linux/xarray.h>
#include <net/psp.h>

#include "psp.h"

static DEFINE_XARRAY_ALLOC1(psp_assocs);
static u32 psp_assoc_next_id;

/**
 * psp_assoc_publish() - add an association to the ID registry
 * @pas: association: an Rx one, or a Tx one with its key installed
 *
 * On success @pas->id is set and the registry holds its own reference.
 *
 * Return: 0 on success, negative errno otherwise.
 */
int psp_assoc_publish(struct psp_assoc *pas)
{
	int err;

	refcount_inc(&pas->refcnt);
	err = xa_alloc_cyclic(&psp_assocs, &pas->id, pas, xa_limit_31b,
			      &psp_assoc_next_id, GFP_KERNEL);
	if (err < 0) {
		pas->id = 0;
		refcount_dec(&pas->refcnt);
		return err;
	}

	return 0;
}

/**
 * psp_assoc_unpublish() - remove an association from the ID registry
 * @pas: association
 *
 * Drops the registry's reference, unless a concurrent caller already did.
 */
void psp_assoc_unpublish(struct psp_assoc *pas)
{
	if (xa_cmpxchg(&psp_assocs, pas->id, pas, NULL, 0) == pas)
		psp_assoc_put(pas);
}

static int psp_assoc_check_access(struct psp_assoc *pas, struct net *net)
{
	struct psp_dev *psd = pas->psd;
	int err;

	mutex_lock(&psd->lock);
	if (psp_dev_is_registered(psd))
		err = psp_dev_check_access(psd, net, true);
	else
		err = -ENODEV;
	mutex_unlock(&psd->lock);

	return err;
}

/**
 * psp_assoc_get_by_id() - look up a published association
 * @net: netns of the caller, must be the netns of the PSP device
 * @id:  association ID
 *
 * Return: association with a reference taken, or NULL.
 */
struct psp_assoc *psp_assoc_get_by_id(struct net *net, u32 id)
{
	struct psp_assoc *pas;

	rcu_read_lock();
	pas = xa_load(&psp_assocs, id);
	if (pas && !refcount_inc_not_zero(&pas->refcnt))
		pas = NULL;
	rcu_read_unlock();

	if (pas && psp_assoc_check_access(pas, net)) {
		psp_assoc_put(pas);
		pas = NULL;
	}

	return pas;
}
EXPORT_SYMBOL_GPL(psp_assoc_get_by_id);

/**
 * psp_assoc_get_next() - iterate over published associations
 * @net:   netns of the caller
 * @index: in: first ID to consider, out: ID of the returned association
 *
 * Return: association with a reference taken, or NULL when done.
 */
struct psp_assoc *psp_assoc_get_next(struct net *net, unsigned long *index)
{
	struct psp_assoc *pas;

	for (;; (*index)++) {
		rcu_read_lock();
		pas = xa_find(&psp_assocs, index, ULONG_MAX, XA_PRESENT);
		if (pas && !refcount_inc_not_zero(&pas->refcnt)) {
			rcu_read_unlock();
			continue;
		}
		rcu_read_unlock();

		if (!pas)
			return NULL;
		if (!psp_assoc_check_access(pas, net))
			return pas;
		psp_assoc_put(pas);
	}
}
