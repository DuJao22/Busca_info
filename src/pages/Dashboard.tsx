import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Globe, Calendar, ArrowRight, FileJson } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const { token } = useAuth();
  const [stats, setStats] = useState({ total: 0, today: 0 });
  const [recentSites, setRecentSites] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const [statsRes, sitesRes] = await Promise.all([
          fetch('/api/stats', { headers: { Authorization: `Bearer ${token}` } }),
          fetch('/api/sites', { headers: { Authorization: `Bearer ${token}` } })
        ]);
        
        const statsData = await statsRes.json();
        const sitesData = await sitesRes.json();
        
        setStats(statsData);
        setRecentSites(sitesData.slice(0, 5)); // Get top 5
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchDashboardData();
  }, [token]);

  if (isLoading) {
    return <div className="flex justify-center py-12"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-600"></div></div>;
  }

  const statCards = [
    { name: 'Total de Análises', value: stats.total, icon: Globe, color: 'bg-blue-500' },
    { name: 'Análises Hoje', value: stats.today, icon: Calendar, color: 'bg-emerald-500' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <h1 className="text-2xl font-bold text-zinc-900">Dashboard</h1>
        <Link
          to="/create"
          className="inline-flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700"
        >
          Nova Análise
        </Link>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        {statCards.map((item) => (
          <div key={item.name} className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-5">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className={`${item.color} rounded-md p-3`}>
                    <item.icon className="h-6 w-6 text-white" aria-hidden="true" />
                  </div>
                </div>
                <div className="ml-5 w-0 flex-1">
                  <dl>
                    <dt className="text-sm font-medium text-zinc-500 truncate">{item.name}</dt>
                    <dd>
                      <div className="text-2xl font-bold text-zinc-900">{item.value}</div>
                    </dd>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-white shadow rounded-lg">
        <div className="px-4 py-5 sm:px-6 flex justify-between items-center border-b border-zinc-200">
          <h3 className="text-lg leading-6 font-medium text-zinc-900">Últimas Análises</h3>
          <Link to="/sites" className="text-sm text-emerald-600 hover:text-emerald-500 flex items-center">
            Ver todas <ArrowRight className="ml-1 w-4 h-4" />
          </Link>
        </div>
        <div className="block sm:hidden">
          <ul className="divide-y divide-zinc-200">
            {recentSites.length === 0 ? (
              <li className="px-4 py-4 text-center text-sm text-zinc-500">Nenhuma análise realizada ainda.</li>
            ) : (
              recentSites.map((site: any) => (
                <li key={site.id} className="px-4 py-4">
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-zinc-900 truncate">{site.name}</p>
                    </div>
                    <div className="ml-2 flex-shrink-0 flex">
                      <p className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-emerald-100 text-emerald-800">
                        {new Date(site.created_at).toLocaleDateString('pt-BR')}
                      </p>
                    </div>
                  </div>
                  <div className="mt-2 sm:flex sm:justify-between">
                    <div className="sm:flex">
                      <p className="flex items-center text-sm text-zinc-500">
                        <FileJson className="flex-shrink-0 mr-1.5 h-4 w-4 text-emerald-600" />
                        {site.slug}
                      </p>
                    </div>
                  </div>
                </li>
              ))
            )}
          </ul>
        </div>
        <div className="hidden sm:block overflow-x-auto">
          <table className="min-w-full divide-y divide-zinc-200">
            <thead className="bg-zinc-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Empresa</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Arquivo</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Data</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-zinc-200">
              {recentSites.length === 0 ? (
                <tr>
                  <td colSpan={3} className="px-6 py-4 text-center text-sm text-zinc-500">Nenhuma análise realizada ainda.</td>
                </tr>
              ) : (
                recentSites.map((site: any) => {
                  return (
                    <tr key={site.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-zinc-900">{site.name}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-zinc-500">
                        <div className="flex items-center space-x-2">
                          <FileJson className="w-4 h-4 text-emerald-600" />
                          <span>{site.slug}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-zinc-500">
                        {new Date(site.created_at).toLocaleDateString('pt-BR')}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
