use crate::error::Result;
use crate::client::{ClientManager, ClientFilter, ClientSystemStats};
use crate::boot::PxeOrchestrator;
use crate::storage::StorageManager;
use crate::auth::AuthManager;
use crate::monitoring::MonitoringManager;
use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use log::{info, error};

#[derive(Clone)]
pub struct WebServer {
    app_state: Arc<AppState>,
    bind_addr: String,
    port: u16,
}

#[derive(Clone)]
pub struct AppState {
    pub client_manager: Arc<RwLock<Option<ClientManager>>>,
    pub pxe_orchestrator: Arc<RwLock<Option<PxeOrchestrator>>>,
    pub storage_manager: Arc<RwLock<Option<Box<dyn StorageManager + Send + Sync>>>>,
    pub auth_manager: Arc<RwLock<Option<AuthManager>>>,
    pub monitoring_manager: Arc<RwLock<Option<MonitoringManager>>>,
}

// API Response types
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub system_overview: SystemOverview,
    pub client_stats: ClientSystemStats,
    pub storage_stats: StorageStats,
    pub network_stats: NetworkStats,
    pub recent_activity: Vec<ActivityEvent>,
}

#[derive(Debug, Serialize)]
pub struct SystemOverview {
    pub uptime: u64,
    pub version: String,
    pub status: String,
    pub services: Vec<ServiceStatus>,
    pub alerts: Vec<SystemAlert>,
}

#[derive(Debug, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub uptime: u64,
    pub health: String,
}

#[derive(Debug, Serialize)]
pub struct SystemAlert {
    pub level: String,
    pub message: String,
    pub timestamp: u64,
    pub component: String,
}

#[derive(Debug, Serialize)]
pub struct StorageStats {
    pub total_images: usize,
    pub total_capacity: u64,
    pub used_capacity: u64,
    pub available_capacity: u64,
    pub recent_snapshots: usize,
}

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub active_dhcp_leases: usize,
    pub tftp_transfers: usize,
    pub iscsi_connections: usize,
    pub bandwidth_usage: BandwidthStats,
}

#[derive(Debug, Serialize)]
pub struct BandwidthStats {
    pub inbound_mbps: f64,
    pub outbound_mbps: f64,
    pub total_gb: f64,
}

#[derive(Debug, Serialize)]
pub struct ActivityEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub description: String,
    pub component: String,
    pub client_id: Option<String>,
}

// API Request types
#[derive(Debug, Deserialize)]
pub struct ClientListQuery {
    pub state: Option<String>,
    pub client_type: Option<String>,
    pub architecture: Option<String>,
    pub online_only: Option<bool>,
    pub failed_only: Option<bool>,
    pub recent_hours: Option<u32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct BootProfileRequest {
    pub name: String,
    pub description: String,
    pub boot_type: String,
    pub architecture: String,
    pub operating_system: String,
    pub kernel_parameters: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ClientAssignmentRequest {
    pub client_id: String,
    pub profile_id: String,
}

impl WebServer {
    pub fn new(bind_addr: String, port: u16) -> Self {
        let app_state = Arc::new(AppState {
            client_manager: Arc::new(RwLock::new(None)),
            pxe_orchestrator: Arc::new(RwLock::new(None)),
            storage_manager: Arc::new(RwLock::new(None)),
            auth_manager: Arc::new(RwLock::new(None)),
            monitoring_manager: Arc::new(RwLock::new(None)),
        });

        Self {
            app_state,
            bind_addr,
            port,
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting web management interface on {}:{}", self.bind_addr, self.port);

        let app = self.create_router().await;
        
        let listener = tokio::net::TcpListener::bind(format!("{}:{}", self.bind_addr, self.port)).await?;
        
        info!("Web management interface listening on {}:{}", self.bind_addr, self.port);
        
        axum::serve(listener, app).await?;
        
        Ok(())
    }

    async fn create_router(&self) -> Router {
        Router::new()
            // Dashboard endpoints
            .route("/api/dashboard", get(get_dashboard_stats))
            .route("/api/dashboard/overview", get(get_system_overview))
            
            // Client management endpoints
            .route("/api/clients", get(list_clients))
            .route("/api/clients/:client_id", get(get_client_info))
            .route("/api/clients/:client_id/history", get(get_client_boot_history))
            .route("/api/clients/:client_id/assign", post(assign_client_profile))
            
            // Boot profile management
            .route("/api/profiles", get(list_boot_profiles))
            .route("/api/profiles", post(create_boot_profile))
            .route("/api/profiles/:profile_id", get(get_boot_profile))
            .route("/api/profiles/:profile_id", put(update_boot_profile))
            .route("/api/profiles/:profile_id", delete(delete_boot_profile))
            
            // Boot session monitoring
            .route("/api/sessions", get(list_boot_sessions))
            .route("/api/sessions/:session_id", get(get_boot_session))
            .route("/api/sessions/:session_id/metrics", get(get_session_metrics))
            
            // Storage management
            .route("/api/storage/images", get(list_storage_images))
            .route("/api/storage/stats", get(get_storage_stats))
            
            // Network monitoring
            .route("/api/network/stats", get(get_network_stats))
            .route("/api/network/dhcp/leases", get(list_dhcp_leases))
            
            // System management
            .route("/api/system/status", get(get_system_status))
            .route("/api/system/services", get(get_services_status))
            .route("/api/system/alerts", get(get_system_alerts))
            
            // Static files for React app
            .route("/", get(serve_index))
            .route("/static/*file", get(serve_static_file))
            
            .layer(CorsLayer::permissive())
            .with_state(self.app_state.clone())
    }

    pub async fn set_client_manager(&self, client_manager: ClientManager) {
        let mut manager_guard = self.app_state.client_manager.write().await;
        *manager_guard = Some(client_manager);
    }

    pub async fn set_pxe_orchestrator(&self, orchestrator: PxeOrchestrator) {
        let mut orchestrator_guard = self.app_state.pxe_orchestrator.write().await;
        *orchestrator_guard = Some(orchestrator);
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping web management interface");
        // The server will stop when start() method completes
        Ok(())
    }
}

// API Handler Functions

async fn get_dashboard_stats(State(state): State<Arc<AppState>>) -> Json<ApiResponse<DashboardStats>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    match get_dashboard_data(&state).await {
        Ok(stats) => Json(ApiResponse {
            success: true,
            data: Some(stats),
            error: None,
            timestamp,
        }),
        Err(e) => {
            error!("Failed to get dashboard stats: {}", e);
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                timestamp,
            })
        }
    }
}

async fn get_system_overview(State(state): State<Arc<AppState>>) -> Json<ApiResponse<SystemOverview>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let overview = SystemOverview {
        uptime: timestamp,
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "Running".to_string(),
        services: vec![
            ServiceStatus {
                name: "DHCP Server".to_string(),
                status: "Active".to_string(),
                uptime: 3600,
                health: "Healthy".to_string(),
            },
            ServiceStatus {
                name: "TFTP Server".to_string(),
                status: "Active".to_string(),
                uptime: 3600,
                health: "Healthy".to_string(),
            },
            ServiceStatus {
                name: "iSCSI Target".to_string(),
                status: "Active".to_string(),
                uptime: 3600,
                health: "Healthy".to_string(),
            },
            ServiceStatus {
                name: "PXE Orchestrator".to_string(),
                status: "Active".to_string(),
                uptime: 3600,
                health: "Healthy".to_string(),
            },
        ],
        alerts: vec![],
    };

    Json(ApiResponse {
        success: true,
        data: Some(overview),
        error: None,
        timestamp,
    })
}

async fn list_clients(
    Query(query): Query<ClientListQuery>, 
    State(state): State<Arc<AppState>>
) -> Json<ApiResponse<Vec<crate::client::ClientInfo>>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let client_manager_guard = state.client_manager.read().await;
    if let Some(client_manager) = client_manager_guard.as_ref() {
        // Convert query parameters to ClientFilter
        let filter = Some(ClientFilter {
            state: query.state.and_then(|s| parse_client_state(&s)),
            client_type: query.client_type.and_then(|t| parse_client_type(&t)),
            architecture: query.architecture.and_then(|a| parse_client_architecture(&a)),
            online_only: query.online_only.unwrap_or(false),
            failed_only: query.failed_only.unwrap_or(false),
            recent_hours: query.recent_hours,
        });

        match client_manager.list_clients(filter).await {
            Ok(mut clients) => {
                // Apply pagination
                if let Some(offset) = query.offset {
                    if offset < clients.len() {
                        clients = clients.into_iter().skip(offset).collect();
                    } else {
                        clients.clear();
                    }
                }
                
                if let Some(limit) = query.limit {
                    clients.truncate(limit);
                }

                Json(ApiResponse {
                    success: true,
                    data: Some(clients),
                    error: None,
                    timestamp,
                })
            }
            Err(e) => Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                timestamp,
            })
        }
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Client manager not available".to_string()),
            timestamp,
        })
    }
}

async fn get_client_info(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>
) -> Json<ApiResponse<crate::client::ClientInfo>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let client_manager_guard = state.client_manager.read().await;
    if let Some(client_manager) = client_manager_guard.as_ref() {
        match client_manager.get_client_info(&client_id).await {
            Ok(Some(client)) => Json(ApiResponse {
                success: true,
                data: Some(client),
                error: None,
                timestamp,
            }),
            Ok(None) => Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Client not found".to_string()),
                timestamp,
            }),
            Err(e) => Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                timestamp,
            }),
        }
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Client manager not available".to_string()),
            timestamp,
        })
    }
}

async fn get_client_boot_history(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>
) -> Json<ApiResponse<Vec<crate::client::ClientBootMetrics>>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let client_manager_guard = state.client_manager.read().await;
    if let Some(client_manager) = client_manager_guard.as_ref() {
        match client_manager.get_client_boot_history(&client_id, Some(20)).await {
            Ok(history) => Json(ApiResponse {
                success: true,
                data: Some(history),
                error: None,
                timestamp,
            }),
            Err(e) => Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                timestamp,
            }),
        }
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Client manager not available".to_string()),
            timestamp,
        })
    }
}

async fn list_boot_profiles(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<String>>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // For now, return mock data
    let profiles = vec![
        "legacy-linux-ubuntu".to_string(),
        "uefi-linux-ubuntu".to_string(),
        "uefi-windows11".to_string(),
    ];

    Json(ApiResponse {
        success: true,
        data: Some(profiles),
        error: None,
        timestamp,
    })
}

async fn get_storage_stats(State(state): State<Arc<AppState>>) -> Json<ApiResponse<StorageStats>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let storage_stats = StorageStats {
        total_images: 15,
        total_capacity: 1024 * 1024 * 1024 * 1024, // 1TB
        used_capacity: 512 * 1024 * 1024 * 1024,   // 512GB
        available_capacity: 512 * 1024 * 1024 * 1024, // 512GB
        recent_snapshots: 3,
    };

    Json(ApiResponse {
        success: true,
        data: Some(storage_stats),
        error: None,
        timestamp,
    })
}

async fn get_network_stats(State(state): State<Arc<AppState>>) -> Json<ApiResponse<NetworkStats>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let network_stats = NetworkStats {
        active_dhcp_leases: 45,
        tftp_transfers: 12,
        iscsi_connections: 38,
        bandwidth_usage: BandwidthStats {
            inbound_mbps: 125.5,
            outbound_mbps: 89.2,
            total_gb: 1.2,
        },
    };

    Json(ApiResponse {
        success: true,
        data: Some(network_stats),
        error: None,
        timestamp,
    })
}

async fn get_system_status(State(state): State<Arc<AppState>>) -> Json<ApiResponse<HashMap<String, String>>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut status = HashMap::new();
    status.insert("status".to_string(), "healthy".to_string());
    status.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    status.insert("uptime".to_string(), "3600".to_string());

    Json(ApiResponse {
        success: true,
        data: Some(status),
        error: None,
        timestamp,
    })
}

async fn serve_index() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLS Management Interface</title>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .status-online { color: #10b981; }
        .status-offline { color: #ef4444; }
        .status-booting { color: #f59e0b; }
        .card { background: white; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 1.5rem; }
    </style>
</head>
<body class="bg-gray-100">
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect } = React;
        
        function DashboardCard({ title, value, subtitle, status }) {
            return (
                <div className="card">
                    <h3 className="text-lg font-semibold text-gray-700">{title}</h3>
                    <div className="mt-2">
                        <div className="text-3xl font-bold text-gray-900">{value}</div>
                        {subtitle && <p className="text-sm text-gray-500">{subtitle}</p>}
                        {status && <span className={`text-sm ${status === 'online' ? 'status-online' : status === 'offline' ? 'status-offline' : 'status-booting'}`}>{status}</span>}
                    </div>
                </div>
            );
        }
        
        function ClientRow({ client }) {
            const getStatusColor = (state) => {
                switch(state) {
                    case 'BootCompleted': return 'text-green-600';
                    case 'Failed': return 'text-red-600';
                    case 'TftpRequested':
                    case 'KernelLoading': return 'text-yellow-600';
                    default: return 'text-gray-600';
                }
            };
            
            return (
                <tr className="border-b">
                    <td className="px-4 py-2">{client.client_id}</td>
                    <td className="px-4 py-2">{client.ip_address || 'N/A'}</td>
                    <td className="px-4 py-2">
                        <span className={getStatusColor(client.state)}>
                            {client.state}
                        </span>
                    </td>
                    <td className="px-4 py-2">{client.client_type}</td>
                    <td className="px-4 py-2">{client.architecture}</td>
                    <td className="px-4 py-2">{client.boot_count}</td>
                    <td className="px-4 py-2">{(client.successful_boots / Math.max(client.boot_count, 1) * 100).toFixed(1)}%</td>
                </tr>
            );
        }
        
        function Dashboard() {
            const [stats, setStats] = useState(null);
            const [clients, setClients] = useState([]);
            const [loading, setLoading] = useState(true);
            const [activeTab, setActiveTab] = useState('dashboard');
            
            useEffect(() => {
                fetchDashboardData();
                fetchClients();
                const interval = setInterval(() => {
                    fetchDashboardData();
                    fetchClients();
                }, 10000); // Refresh every 10 seconds
                return () => clearInterval(interval);
            }, []);
            
            const fetchDashboardData = async () => {
                try {
                    const response = await fetch('/api/dashboard/overview');
                    const result = await response.json();
                    if (result.success) {
                        setStats(result.data);
                    }
                } catch (error) {
                    console.error('Failed to fetch dashboard data:', error);
                }
                setLoading(false);
            };
            
            const fetchClients = async () => {
                try {
                    const response = await fetch('/api/clients?limit=50');
                    const result = await response.json();
                    if (result.success) {
                        setClients(result.data || []);
                    }
                } catch (error) {
                    console.error('Failed to fetch clients:', error);
                }
            };
            
            if (loading) {
                return (
                    <div className="flex justify-center items-center h-screen">
                        <div className="text-xl">Loading DLS Management Interface...</div>
                    </div>
                );
            }
            
            return (
                <div className="min-h-screen">
                    {/* Header */}
                    <header className="bg-blue-600 text-white shadow-lg">
                        <div className="max-w-7xl mx-auto px-4 py-6">
                            <h1 className="text-3xl font-bold">DLS Management Interface</h1>
                            <p className="text-blue-100">Diskless Boot System Dashboard</p>
                        </div>
                    </header>
                    
                    {/* Navigation */}
                    <nav className="bg-white shadow-sm border-b">
                        <div className="max-w-7xl mx-auto px-4">
                            <div className="flex space-x-8">
                                <button
                                    className={`py-4 px-2 border-b-2 font-medium text-sm ${activeTab === 'dashboard' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
                                    onClick={() => setActiveTab('dashboard')}
                                >
                                    Dashboard
                                </button>
                                <button
                                    className={`py-4 px-2 border-b-2 font-medium text-sm ${activeTab === 'clients' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
                                    onClick={() => setActiveTab('clients')}
                                >
                                    Clients
                                </button>
                                <button
                                    className={`py-4 px-2 border-b-2 font-medium text-sm ${activeTab === 'storage' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
                                    onClick={() => setActiveTab('storage')}
                                >
                                    Storage
                                </button>
                                <button
                                    className={`py-4 px-2 border-b-2 font-medium text-sm ${activeTab === 'network' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
                                    onClick={() => setActiveTab('network')}
                                >
                                    Network
                                </button>
                            </div>
                        </div>
                    </nav>
                    
                    <main className="max-w-7xl mx-auto px-4 py-8">
                        {activeTab === 'dashboard' && (
                            <div>
                                {/* System Status Cards */}
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                                    <DashboardCard
                                        title="System Status"
                                        value={stats?.status || 'Unknown'}
                                        subtitle={`Version ${stats?.version || 'N/A'}`}
                                        status="online"
                                    />
                                    <DashboardCard
                                        title="Active Clients"
                                        value={clients.filter(c => c.state !== 'Offline').length}
                                        subtitle={`${clients.length} total clients`}
                                    />
                                    <DashboardCard
                                        title="Boot Success Rate"
                                        value={`${(clients.reduce((acc, c) => acc + (c.successful_boots / Math.max(c.boot_count, 1)), 0) / Math.max(clients.length, 1) * 100).toFixed(1)}%`}
                                        subtitle="Overall success rate"
                                    />
                                    <DashboardCard
                                        title="Services"
                                        value={stats?.services?.filter(s => s.status === 'Active').length || 0}
                                        subtitle={`${stats?.services?.length || 0} total services`}
                                        status="online"
                                    />
                                </div>
                                
                                {/* Services Status */}
                                <div className="card mb-8">
                                    <h2 className="text-xl font-semibold mb-4">Service Status</h2>
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                        {stats?.services?.map((service, index) => (
                                            <div key={index} className="p-4 border rounded-lg">
                                                <h3 className="font-semibold">{service.name}</h3>
                                                <span className={`text-sm ${service.status === 'Active' ? 'status-online' : 'status-offline'}`}>
                                                    {service.status}
                                                </span>
                                                <div className="text-xs text-gray-500">{service.health}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}
                        
                        {activeTab === 'clients' && (
                            <div>
                                <div className="card">
                                    <h2 className="text-xl font-semibold mb-4">Client Management</h2>
                                    <div className="overflow-x-auto">
                                        <table className="min-w-full">
                                            <thead className="bg-gray-50">
                                                <tr>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Client ID</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Architecture</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Boot Count</th>
                                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Success Rate</th>
                                                </tr>
                                            </thead>
                                            <tbody className="bg-white">
                                                {clients.map((client, index) => (
                                                    <ClientRow key={index} client={client} />
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        )}
                        
                        {activeTab === 'storage' && (
                            <div>
                                <div className="card">
                                    <h2 className="text-xl font-semibold mb-4">Storage Management</h2>
                                    <p className="text-gray-600">Storage management features will be available in the next release.</p>
                                </div>
                            </div>
                        )}
                        
                        {activeTab === 'network' && (
                            <div>
                                <div className="card">
                                    <h2 className="text-xl font-semibold mb-4">Network Monitoring</h2>
                                    <p className="text-gray-600">Network monitoring features will be available in the next release.</p>
                                </div>
                            </div>
                        )}
                    </main>
                </div>
            );
        }
        
        ReactDOM.render(<Dashboard />, document.getElementById('root'));
    </script>
</body>
</html>"#
}

// Placeholder handlers for endpoints not fully implemented yet
async fn assign_client_profile(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn create_boot_profile(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn get_boot_profile(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn update_boot_profile(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn delete_boot_profile(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn list_boot_sessions(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<String>>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: true, data: Some(vec![]), error: None, timestamp })
}

async fn get_boot_session(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn get_session_metrics(State(state): State<Arc<AppState>>) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: false, data: None, error: Some("Not implemented".to_string()), timestamp })
}

async fn list_storage_images(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<String>>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: true, data: Some(vec![]), error: None, timestamp })
}

async fn list_dhcp_leases(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<String>>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: true, data: Some(vec![]), error: None, timestamp })
}

async fn get_services_status(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<ServiceStatus>>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let services = vec![
        ServiceStatus { name: "DHCP Server".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
        ServiceStatus { name: "TFTP Server".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
        ServiceStatus { name: "iSCSI Target".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
    ];
    Json(ApiResponse { success: true, data: Some(services), error: None, timestamp })
}

async fn get_system_alerts(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<SystemAlert>>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    Json(ApiResponse { success: true, data: Some(vec![]), error: None, timestamp })
}

async fn serve_static_file(Path(file): Path<String>) -> &'static str {
    // Placeholder for static file serving
    "Static file not found"
}

// Helper functions
async fn get_dashboard_data(state: &AppState) -> Result<DashboardStats> {
    let client_manager_guard = state.client_manager.read().await;
    
    let client_stats = if let Some(client_manager) = client_manager_guard.as_ref() {
        client_manager.get_system_stats().await.unwrap_or_default()
    } else {
        crate::client::ClientSystemStats {
            total_clients: 0,
            online_clients: 0,
            offline_clients: 0,
            booting_clients: 0,
            failed_clients: 0,
            total_boot_sessions: 0,
            successful_boot_sessions: 0,
            failed_boot_sessions: 0,
            boot_success_rate: 0.0,
            average_boot_time: 0,
            active_boot_sessions: 0,
        }
    };
    
    let system_overview = SystemOverview {
        uptime: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "Running".to_string(),
        services: vec![
            ServiceStatus { name: "DHCP Server".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
            ServiceStatus { name: "TFTP Server".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
            ServiceStatus { name: "iSCSI Target".to_string(), status: "Active".to_string(), uptime: 3600, health: "Healthy".to_string() },
        ],
        alerts: vec![],
    };

    Ok(DashboardStats {
        system_overview,
        client_stats,
        storage_stats: StorageStats {
            total_images: 15,
            total_capacity: 1024 * 1024 * 1024 * 1024,
            used_capacity: 512 * 1024 * 1024 * 1024,
            available_capacity: 512 * 1024 * 1024 * 1024,
            recent_snapshots: 3,
        },
        network_stats: NetworkStats {
            active_dhcp_leases: 45,
            tftp_transfers: 12,
            iscsi_connections: 38,
            bandwidth_usage: BandwidthStats {
                inbound_mbps: 125.5,
                outbound_mbps: 89.2,
                total_gb: 1.2,
            },
        },
        recent_activity: vec![],
    })
}

fn parse_client_state(state_str: &str) -> Option<crate::client::ClientState> {
    match state_str {
        "Unknown" => Some(crate::client::ClientState::Unknown),
        "Discovered" => Some(crate::client::ClientState::Discovered),
        "DhcpAssigned" => Some(crate::client::ClientState::DhcpAssigned),
        "TftpRequested" => Some(crate::client::ClientState::TftpRequested),
        "KernelLoading" => Some(crate::client::ClientState::KernelLoading),
        "IscsiConnected" => Some(crate::client::ClientState::IscsiConnected),
        "BootCompleted" => Some(crate::client::ClientState::BootCompleted),
        "Failed" => Some(crate::client::ClientState::Failed),
        "Offline" => Some(crate::client::ClientState::Offline),
        _ => None,
    }
}

fn parse_client_type(type_str: &str) -> Option<crate::client::ClientType> {
    match type_str {
        "LegacyBios" => Some(crate::client::ClientType::LegacyBios),
        "UefiBios" => Some(crate::client::ClientType::UefiBios),
        "Unknown" => Some(crate::client::ClientType::Unknown),
        _ => None,
    }
}

fn parse_client_architecture(arch_str: &str) -> Option<crate::client::ClientArchitecture> {
    match arch_str {
        "X86" => Some(crate::client::ClientArchitecture::X86),
        "X64" => Some(crate::client::ClientArchitecture::X64),
        "Arm32" => Some(crate::client::ClientArchitecture::Arm32),
        "Arm64" => Some(crate::client::ClientArchitecture::Arm64),
        "Unknown" => Some(crate::client::ClientArchitecture::Unknown),
        _ => None,
    }
}

impl Default for crate::client::ClientSystemStats {
    fn default() -> Self {
        Self {
            total_clients: 0,
            online_clients: 0,
            offline_clients: 0,
            booting_clients: 0,
            failed_clients: 0,
            total_boot_sessions: 0,
            successful_boot_sessions: 0,
            failed_boot_sessions: 0,
            boot_success_rate: 0.0,
            average_boot_time: 0,
            active_boot_sessions: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_web_server_creation() {
        let web_server = WebServer::new("127.0.0.1".to_string(), 8080);
        assert_eq!(web_server.bind_addr, "127.0.0.1");
        assert_eq!(web_server.port, 8080);
    }

    #[test]
    fn test_parse_client_state() {
        assert_eq!(parse_client_state("Unknown"), Some(crate::client::ClientState::Unknown));
        assert_eq!(parse_client_state("BootCompleted"), Some(crate::client::ClientState::BootCompleted));
        assert_eq!(parse_client_state("InvalidState"), None);
    }

    #[test]
    fn test_parse_client_type() {
        assert_eq!(parse_client_type("LegacyBios"), Some(crate::client::ClientType::LegacyBios));
        assert_eq!(parse_client_type("UefiBios"), Some(crate::client::ClientType::UefiBios));
        assert_eq!(parse_client_type("InvalidType"), None);
    }

    #[test]
    fn test_api_response_structure() {
        let response: ApiResponse<String> = ApiResponse {
            success: true,
            data: Some("test".to_string()),
            error: None,
            timestamp: 1640000000,
        };
        
        assert!(response.success);
        assert!(response.data.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_dashboard_stats_structure() {
        let stats = DashboardStats {
            system_overview: SystemOverview {
                uptime: 3600,
                version: "1.0.0".to_string(),
                status: "Running".to_string(),
                services: vec![],
                alerts: vec![],
            },
            client_stats: crate::client::ClientSystemStats::default(),
            storage_stats: StorageStats {
                total_images: 10,
                total_capacity: 1024,
                used_capacity: 512,
                available_capacity: 512,
                recent_snapshots: 2,
            },
            network_stats: NetworkStats {
                active_dhcp_leases: 25,
                tftp_transfers: 5,
                iscsi_connections: 20,
                bandwidth_usage: BandwidthStats {
                    inbound_mbps: 100.0,
                    outbound_mbps: 80.0,
                    total_gb: 1.0,
                },
            },
            recent_activity: vec![],
        };
        
        assert_eq!(stats.system_overview.version, "1.0.0");
        assert_eq!(stats.storage_stats.total_images, 10);
        assert_eq!(stats.network_stats.active_dhcp_leases, 25);
    }
}