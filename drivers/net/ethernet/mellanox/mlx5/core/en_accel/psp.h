/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5E_ACCEL_PSP_H__
#define __MLX5E_ACCEL_PSP_H__
#if IS_ENABLED(CONFIG_MLX5_EN_PSP)
#include <net/psp/types.h>
#include "en.h"

struct mlx5e_psp_stats {
	u64 psp_rx_pkts;
	u64 psp_rx_bytes;
	u64 psp_rx_pkts_auth_fail;
	u64 psp_rx_bytes_auth_fail;
	u64 psp_rx_pkts_frame_err;
	u64 psp_rx_bytes_frame_err;
	u64 psp_rx_pkts_drop;
	u64 psp_rx_bytes_drop;
	u64 psp_tx_pkts;
	u64 psp_tx_bytes;
	u64 psp_tx_pkts_drop;
	u64 psp_tx_bytes_drop;
};

struct mlx5e_psp {
	struct psp_dev *psd;
	struct psp_dev_caps caps;
	struct mlx5e_psp_fs *fs;
	atomic_t tx_key_cnt;
	atomic_t tx_drop;
	/* switchdev: decryption in the FDB, see psp_fdb.c */
	struct mutex fdb_rx_lock;
	/* the counters of FDB Rx and Tx tables freed so far */
	struct mlx5e_psp_stats fdb_rx_stats;
	struct mlx5e_psp_fdb_rx *fdb_rx;
	struct mlx5e_psp_fdb_tx *fdb_tx;
	struct mlx5e_psp_fdb_host_tx *fdb_host_tx;
};

static inline bool mlx5_is_psp_device(struct mlx5_core_dev *mdev)
{
	if (!MLX5_CAP_GEN(mdev, psp))
		return false;

	if (!MLX5_CAP_PSP(mdev, psp_crypto_offload) ||
	    !MLX5_CAP_PSP(mdev, psp_crypto_esp_aes_gcm_128_encrypt) ||
	    !MLX5_CAP_PSP(mdev, psp_crypto_esp_aes_gcm_128_decrypt))
		return false;

	return true;
}

void mlx5_accel_psp_fs_cleanup_rx_tables(struct mlx5e_priv *priv);
void mlx5_accel_psp_fs_cleanup_tx_tables(struct mlx5e_priv *priv);
int mlx5e_psp_register(struct mlx5e_priv *priv);
void mlx5e_psp_unregister(struct mlx5e_priv *priv);
int mlx5e_psp_init(struct mlx5e_priv *priv);
void mlx5e_psp_cleanup(struct mlx5e_priv *priv);
int mlx5e_psp_init_switchdev(struct mlx5e_priv *priv);
bool mlx5e_psp_fdb_steering_ok(struct mlx5_core_dev *mdev);
void mlx5e_psp_cleanup_switchdev(struct mlx5e_priv *priv);
int mlx5e_psp_tx_key_id(struct mlx5e_priv *priv, struct psp_assoc *pas,
			u32 *id);
#if IS_ENABLED(CONFIG_MLX5_CLS_ACT)
int mlx5e_psp_fdb_rx_get(struct mlx5e_priv *priv);
void mlx5e_psp_fdb_rx_put(struct mlx5e_priv *priv);
struct mlx5_flow_table *mlx5e_psp_fdb_tx_get(struct mlx5e_priv *priv);
void mlx5e_psp_fdb_tx_put(struct mlx5e_priv *priv);
int mlx5e_psp_fdb_host_tx_create(struct mlx5e_priv *priv);
void mlx5e_psp_fdb_host_tx_destroy(struct mlx5e_priv *priv);
void mlx5e_psp_fdb_host_tx_update_next(struct mlx5_core_dev *mdev);
void mlx5e_psp_fdb_rx_get_stats(struct mlx5e_priv *priv,
				struct mlx5e_psp_stats *stats);
#else
static inline int mlx5e_psp_fdb_host_tx_create(struct mlx5e_priv *priv)
{
	return -EOPNOTSUPP;
}

static inline void mlx5e_psp_fdb_host_tx_destroy(struct mlx5e_priv *priv) { }
static inline void
mlx5e_psp_fdb_host_tx_update_next(struct mlx5_core_dev *mdev) { }
static inline void mlx5e_psp_fdb_rx_get_stats(struct mlx5e_priv *priv,
					      struct mlx5e_psp_stats *stats) { }
#endif
#else
static inline void mlx5_accel_psp_fs_cleanup_rx_tables(struct mlx5e_priv *priv) { }
static inline void mlx5_accel_psp_fs_cleanup_tx_tables(struct mlx5e_priv *priv) { }
static inline bool mlx5_is_psp_device(struct mlx5_core_dev *mdev)
{
	return false;
}

static inline int mlx5e_psp_register(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_psp_unregister(struct mlx5e_priv *priv) { }
static inline int mlx5e_psp_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_psp_cleanup(struct mlx5e_priv *priv) { }
static inline int mlx5e_psp_init_switchdev(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_psp_cleanup_switchdev(struct mlx5e_priv *priv) { }
static inline void
mlx5e_psp_fdb_host_tx_update_next(struct mlx5_core_dev *mdev) { }
#endif /* CONFIG_MLX5_EN_PSP */
#endif /* __MLX5E_ACCEL_PSP_H__ */
