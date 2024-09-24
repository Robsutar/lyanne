use super::*;

async fn create_read_handler<Skt, N: NodeInternalExt<Skt>>(weak_internal: Weak<N>) {
    let mut was_used = false;
    'l1: loop {
        if let Some(internal) = N::try_upgrade(&weak_internal) {
            if *internal
                .sub()
                .read_handler_properties
                .active_count
                .write()
                .unwrap()
                > internal.sub().read_handler_properties.target_surplus_size + 1
            {
                let mut surplus_count = internal
                    .sub()
                    .read_handler_properties
                    .active_count
                    .write()
                    .unwrap();
                if !was_used {
                    *surplus_count -= 1;
                }
                break 'l1;
            } else {
                let read_timeout = internal.sub().messaging_properties.timeout_interpretation;
                let socket = Arc::clone(&internal.sub().socket);
                drop(internal);

                let pre_read_next_bytes_result =
                    N::pre_read_next_bytes_timeout(&socket, read_timeout).await;

                match N::try_upgrade_or_get_inactive(&weak_internal).await {
                    Some(Ok(server)) => match pre_read_next_bytes_result {
                        Ok(result) => {
                            if !was_used {
                                was_used = true;
                                let mut surplus_count = server
                                    .sub()
                                    .read_handler_properties
                                    .active_count
                                    .write()
                                    .unwrap();
                                *surplus_count -= 1;
                            }

                            #[cfg(feature = "store_unexpected")]
                            let addr = result.0.clone();

                            let _read_result = server.read_next_bytes(result).await;

                            #[cfg(feature = "store_unexpected")]
                            if _read_result.is_unexpected() {
                                let _ = server
                                    .store_unexpected_errors
                                    .error_sender
                                    .send(UnexpectedError::OfReadAddrBytes(addr, _read_result))
                                    .await;
                            }
                        }
                        Err(_) => {
                            if was_used {
                                was_used = false;
                                let mut surplus_count = server
                                    .sub()
                                    .read_handler_properties
                                    .active_count
                                    .write()
                                    .unwrap();
                                *surplus_count += 1;
                            }
                        }
                    },
                    Some(Err(inactive_state)) => {
                        if let Ok(result) = pre_read_next_bytes_result {
                            let _ = inactive_state.received_bytes_sender.try_send(result);
                        }
                        break 'l1;
                    }
                    None => {
                        break 'l1;
                    }
                }
            }
        } else {
            break 'l1;
        }
    }
}
